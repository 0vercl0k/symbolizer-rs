// Axel '0vercl0k' Souchet - February 20 2024
//! This module contains the implementation of the [`Symbolizer`] which is the
//! object that is able to symbolize files using PDB information if available.
use std::cell::RefCell;
use std::collections::{hash_map, HashMap};
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, stdout, BufReader, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};
use kdmp_parser::KernelDumpParser;
use log::{debug, trace, warn};

use crate::hex_addrs_iter::HexAddressesIterator;
use crate::misc::{fast_hex32, fast_hex64};
use crate::modules::{Module, Modules};
use crate::pdbcache::{PdbCache, PdbCacheBuilder};
use crate::pe::{PdbId, Pe};
use crate::stats::{Stats, StatsBuilder};
use crate::CliArgs;

/// Format a path to find a PDB in a symbol cache.
///
/// Here is an example:
/// ```text
/// C:\work\dbg\sym\ntfs.pdb\64D20DCBA29FFC0CD355FFE7440EC5F81\ntfs.pdb
/// ^^^^^^^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^
///   cache path    PDB name PDB GUID & PDB Age                PDB name
/// ```
pub fn format_pdb_path(symsrv_cache: &Path, pdb_id: &PdbId) -> PathBuf {
    let pdb_name = pdb_id.name();
    symsrv_cache
        .join(&pdb_name)
        .join(format!("{}{:x}", pdb_id.guid, pdb_id.age,))
        .join(&pdb_name)
}

/// Format a URL to find a PDB on an HTTP symbol server.
pub fn format_pdb_url(symsrv: &str, pdb_id: &PdbId) -> String {
    // It seems that Chrome's symsrv server only accepts the GUID/age part as
    // uppercase hex, so let's use that.
    format!(
        "{symsrv}/{}/{}{:x}/{}",
        pdb_id.name(),
        pdb_id.guid,
        pdb_id.age,
        pdb_id.name()
    )
}

/// Download a PDB file from a candidate symbol servers.
///
/// The code iterates through every symbol servers, and stops as soon as it was
/// able to download a matching file.
pub fn try_download_from_guid(
    symsrvs: &Vec<String>,
    sympath_dir: impl AsRef<Path>,
    pdb_id: &PdbId,
) -> Result<Option<PathBuf>> {
    // Give a try to each of the symbol servers.
    for symsrv in symsrvs {
        debug!(
            "trying to download pdb for {} from {}..",
            pdb_id.name(),
            symsrv
        );

        // The way a symbol path is structured is that there is a directory per module..
        let sympath_dir = sympath_dir.as_ref();
        let pdb_root_dir = sympath_dir.join(pdb_id.name());

        // ..and inside, there is a directory per version of the PDB..
        let pdb_dir = pdb_root_dir.join(format!("{}{:x}", pdb_id.guid, pdb_id.age));

        // ..and finally the PDB file itself.
        let pdb_path = pdb_dir.join(pdb_id.name());

        // The file doesn't exist on the file system, so let's try to download it from a
        // symbol server.
        let pdb_url = format_pdb_url(symsrv, pdb_id);
        let resp = match ureq::get(&pdb_url).call() {
            Ok(o) => o,
            // If we get a 404, it means that the server doesn't know about this file. So we'll skip
            // to the next symbol server.
            Err(ureq::Error::Status(404, ..)) => {
                warn!("got a 404 for {pdb_url}");
                continue;
            }
            // If we received any other errors, well that's not expected so let's bail.
            Err(e) => bail!("failed to download pdb {pdb_url}: {e}"),
        };

        // If the server knows about this file, it is time to create the directory
        // structure in which we'll download the file into.
        if !(pdb_root_dir.try_exists()?) {
            debug!("creating {pdb_root_dir:?}..");
            fs::create_dir(&pdb_root_dir)
                .with_context(|| format!("failed to create base pdb dir {pdb_root_dir:?}"))?;
        }

        if !pdb_dir.try_exists()? {
            debug!("creating {pdb_dir:?}..");
            fs::create_dir(&pdb_dir)
                .with_context(|| format!("failed to create pdb dir {pdb_dir:?}"))?;
        }

        // Finally, we can download and save the file.
        let file =
            File::create(&pdb_path).with_context(|| format!("failed to create {pdb_path:?}"))?;

        io::copy(&mut resp.into_reader(), &mut BufWriter::new(file))?;

        debug!("downloaded to {pdb_path:?}");
        return Ok(Some(pdb_path));
    }

    Ok(None)
}

/// Create the output file from an input.
///
/// This logic was moved into a function to be able to handle the `--overwrite`
/// logic and to handle the case when `output` is a directory path and not a
/// file path. In that case, we will create a file with the same input file
/// name, but with a specific suffix.
fn get_output_file(args: &CliArgs, input: &Path, output: &Path) -> Result<File> {
    let output_path = if output.is_dir() {
        // If the output is a directory, then we'll create a file that has the same file
        // name as the input, but with a suffix.
        let path = input.with_extension("symbolized.txt");
        let filename = path.file_name().ok_or_else(|| anyhow!("no file name"))?;

        output.join(filename)
    } else {
        // If the output path is already a file path, then we'll use it as is.
        output.into()
    };

    // If the output exists, we'll want the user to tell us to overwrite those
    // files.
    if output_path.exists() && !args.overwrite {
        // If they don't we will bail.
        bail!(
            "{} already exists, run with --overwrite",
            output_path.display()
        );
    }

    // We can now create the output file!
    File::create(output_path.clone())
        .with_context(|| format!("failed to create output file {output_path:?}"))
}

/// Where did we find this PDB? On the file-system somewhere, in a local symbol
/// cache or downloaded on a symbol server.
///
/// This is used mainly to account for statistics; how many files were
/// downloaded, etc.
enum PdbKind {
    /// The PDB file was found on the file system but no in a symbol cache.
    Local,
    /// The PDB file was found on the file system in a local symbol cache.
    LocalCache,
    /// The PDB file was downloaded on a remote symbol server.
    Download,
}

/// Try to find a PDB file online or locally from a [`PdbId`].
fn get_pdb(
    sympath: &Path,
    symsrvs: &Vec<String>,
    pdb_id: &PdbId,
) -> Result<Option<(PathBuf, PdbKind)>> {
    // Let's see if the path exists locally..
    if pdb_id.path.is_file() {
        // .. if it does, this is a 'Local' PDB.
        return Ok(Some((pdb_id.path.clone(), PdbKind::Local)));
    }

    // Now, let's see if it's in the local cache..
    let local_path = format_pdb_path(sympath, pdb_id);
    if local_path.is_file() {
        // .. if it does, this is a 'LocalCache' PDB.
        return Ok(Some((local_path, PdbKind::LocalCache)));
    }

    // The last resort is to try to download it...
    let downloaded_path = try_download_from_guid(symsrvs, sympath, pdb_id)
        .with_context(|| format!("failed to download PDB for {pdb_id}"))?;

    Ok(downloaded_path.map(|p| (p, PdbKind::Download)))
}

/// A simple 'hasher' that uses the input bytes as a hash.
///
/// This is used for the cache HashMap used in the [`Symbolizer`]. We are
/// caching symbol addresses and so we know those addresses are unique and do
/// not need to be hashed.
#[derive(Default)]
struct IdentityHasher {
    h: u64,
}

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.h
    }

    fn write(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), 8);

        self.h = u64::from_le_bytes(bytes.try_into().unwrap());
    }
}

impl BuildHasher for IdentityHasher {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

/// The [`Symbolizer`] is the main object that glues all the logic.
///
/// It downloads, parses PDB information, and symbolizes.
pub struct Symbolizer {
    /// Keep track of some statistics regarding the number of lines symbolized,
    /// PDB downloaded, etc.
    stats: StatsBuilder,
    /// This is a path to the local PDB symbol cache where PDBs will be
    /// downloaded into / where some are available.
    symcache: PathBuf,
    /// This is the list of kernel / user modules read from the kernel crash
    /// dump.
    modules: Modules,
    /// The kernel dump parser. We need this to be able to read PDB identifiers
    /// out of the PE headers, as well as reading the export tables of those
    /// modules.
    parser: KernelDumpParser,
    /// List of symbol servers to try to download PDBs from when needed.
    symsrvs: Vec<String>,
    /// Caches addresses to symbols. This allows us to not have to symbolize an
    /// address again.
    addr_cache: RefCell<HashMap<u64, Rc<String>, IdentityHasher>>,
    /// Each parsed module is stored in this cache. We parse PDBs, etc. only
    /// once and then the [`PdbCache`] is used to query.
    pdb_caches: RefCell<HashMap<Range<u64>, Rc<PdbCache>>>,
}

impl Symbolizer {
    /// Create a symbolizer.
    ///
    /// The `symcache` is used both for reading existing PDBs as well as writing
    /// the newly downloaded ones, the `parser` is used to enumerate the kernel
    /// / user modules loaded at the crash-dump time as well as reading PDB
    /// identifiers off the modules' PE headers, and the HTTP symbol servers are
    /// a list of servers that will get contacted to try to find one that knows
    /// about a specific PDB file.
    pub fn new(
        symcache: impl AsRef<Path>,
        parser: KernelDumpParser,
        symsrvs: Vec<String>,
    ) -> Result<Self> {
        // Read both the user & kernel modules from the dump file.
        let mut modules = Vec::new();
        for (at, name) in parser.user_modules().chain(parser.kernel_modules()) {
            let (_, filename) = name.rsplit_once('\\').unwrap_or((name, name));
            modules.push(Module::new(
                filename.to_string(),
                at.start.into(),
                at.end.into(),
            ));
        }

        Ok(Self {
            stats: Default::default(),
            symcache: symcache.as_ref().to_path_buf(),
            modules: Modules::new(modules),
            parser,
            symsrvs,
            addr_cache: Default::default(),
            pdb_caches: Default::default(),
        })
    }

    /// Start the stopwatch.
    pub fn start_stopwatch(&self) {
        self.stats.start()
    }

    /// Stop the stopwatch and get a copy of the [`Stats`].
    pub fn stop_stopwatch(self) -> Stats {
        self.stats.stop()
    }

    /// Get the [`PdbCache`] for a specified `addr`.
    pub fn module_pdbcache(&self, addr: u64) -> Option<Rc<PdbCache>> {
        self.pdb_caches.borrow().iter().find_map(|(k, v)| {
            if k.contains(&addr) {
                Some(v.clone())
            } else {
                None
            }
        })
    }

    /// Try to symbolize an address.
    ///
    /// If there's a [`PdbCache`] already created, then ask it to symbolize.
    /// Otherwise, this will create a [`PdbCache`], try to find a PDB (locally
    /// or remotely) and extract every bit of relevant information for us.
    /// Finally, the result will be kept around to symbolize addresses in that
    /// module faster in the future.
    pub fn try_symbolize_addr_from_pdbs(&self, addr: u64) -> Result<Option<Rc<String>>> {
        trace!("symbolizing address {addr:#x}..");
        let Some(module) = self.modules.find(addr) else {
            trace!("address {addr:#x} doesn't belong to any module");
            return Ok(None);
        };

        trace!("address {addr:#x} found in {}", module.name);

        // Do we have a cache already ready to go?
        if let Some(pdbcache) = self.module_pdbcache(addr) {
            return Ok(Some(Rc::new(pdbcache.symbolize(module.rva(addr))?)));
        }

        // Otherwise, let's make one.
        let mut builder = PdbCacheBuilder::new(module);

        // Let's start by parsing the PE to get its exports, and PDB information if
        // there's any.
        let pe = Pe::new(&self.parser, module.at.start)?;

        // Ingest the EAT.
        builder.ingest(pe.exports.into_iter());

        // .. and see if it has PDB information.
        trace!("Get PDB information for {module:?}..");

        if let Some(pdb_id) = pe.pdb_id {
            // Try to get a PDB..
            let pdb_path = get_pdb(&self.symcache, &self.symsrvs, &pdb_id)?;

            // .. and ingest it if we have one.
            if let Some((pdb_path, pdb_kind)) = pdb_path {
                if matches!(pdb_kind, PdbKind::Download) {
                    self.stats.downloaded_file(pdb_path.metadata()?.len())
                }

                builder.ingest_pdb(pdb_path)?;
            }
        }

        // Build the cache..
        let pdbcache = builder.build()?;

        // .. symbolize `addr`..
        let line = pdbcache
            .symbolize(module.rva(addr))
            .with_context(|| format!("failed to symbolize {addr:#x}"))?;

        // .. and store the sym cache to be used for next time we need to symbolize an
        // address from this module.
        assert!(self
            .pdb_caches
            .borrow_mut()
            .insert(module.at.clone(), Rc::new(pdbcache))
            .is_none());

        Ok(Some(Rc::new(line)))
    }

    /// Try to symbolize an address.
    ///
    /// If the address has been symbolized before, it will be in the
    /// `addr_cache` already. If not, we need to take the slow path and ask the
    /// right [`PdbCache`] which might require to create one in the first place.
    pub fn try_symbolize_addr(&self, addr: u64) -> Result<Option<Rc<String>>> {
        match self.addr_cache.borrow_mut().entry(addr) {
            hash_map::Entry::Occupied(o) => {
                self.stats.cache_hit();
                return Ok(Some(o.get().clone()));
            }
            hash_map::Entry::Vacant(v) => {
                let Some(symbol) = self.try_symbolize_addr_from_pdbs(addr)? else {
                    return Ok(None);
                };

                v.insert(symbol);
            }
        };

        Ok(self.addr_cache.borrow().get(&addr).cloned())
    }

    /// Symbolize `addr` in the `module+offset` style and write the result into
    /// `output`.
    fn modoff(&mut self, output: &mut impl Write, addr: u64) -> Result<()> {
        let mut buffer = [0; 16];
        if let Some(module) = self.modules.find(addr) {
            output.write_all(module.name.as_bytes())?;
            output.write_all(&[b'+', b'0', b'x'])?;

            output.write_all(fast_hex32(
                &mut buffer[0..8].try_into().unwrap(),
                module.rva(addr),
            ))
        } else {
            output.write_all(&[b'0', b'x'])?;

            output.write_all(fast_hex64(&mut buffer, addr))
        }
        .context("failed to write symbolized value to output")?;

        output
            .write_all(&[b'\n'])
            .context("failed to write line feed modoff addr")
    }

    /// Symbolize `addr` in the `module!function+offset` style and write the
    /// result into `output`.
    fn full(&mut self, output: &mut impl Write, addr: u64) -> Result<()> {
        match self.try_symbolize_addr(addr)? {
            Some(sym) => {
                output
                    .write_all(sym.as_bytes())
                    .context("failed to write symbolized value to output")?;
                output
                    .write_all(&[b'\n'])
                    .context("failed to write line feed")
            }
            None => self.modoff(output, addr),
        }
    }

    /// Process an input file and symbolize every line.
    pub fn process_file(&mut self, trace_path: impl AsRef<Path>, args: &CliArgs) -> Result<usize> {
        let trace_path = trace_path.as_ref();
        let input = File::open(trace_path)
            .with_context(|| format!("failed to open {}", trace_path.display()))?;

        let writer: Box<dyn Write> = match &args.output {
            Some(output) => Box::new(get_output_file(args, trace_path, output)?),
            None => Box::new(stdout()),
        };

        let mut output = BufWriter::with_capacity(args.out_buffer_size, writer);
        let mut line_number = 1 + args.skip;
        let mut lines_symbolized = 1;
        let max_line = args.max.unwrap_or(usize::MAX);
        let reader = BufReader::with_capacity(args.in_buffer_size, input);
        for addr in HexAddressesIterator::new(reader).skip(args.skip) {
            let addr = addr.with_context(|| {
                format!(
                    "failed to get hex addr from l{line_number} of {}",
                    trace_path.display()
                )
            })?;

            if args.line_numbers {
                let mut buffer = itoa::Buffer::new();
                output.write_all(&[b'l'])?;
                output.write_all(buffer.format(line_number).as_bytes())?;
                output.write_all(&[b':', b' '])?;
            }

            match args.style {
                crate::SymbolStyle::Modoff => self.modoff(&mut output, addr),
                crate::SymbolStyle::Full => self.full(&mut output, addr),
            }
            .with_context(|| {
                format!(
                    "failed to symbolize l{line_number} of {}",
                    trace_path.display()
                )
            })?;

            if lines_symbolized >= max_line {
                println!(
                    "Hit maximum line limit {} for {}",
                    max_line,
                    trace_path.display()
                );
                break;
            }

            lines_symbolized += 1;
            line_number += 1;
        }

        self.stats.done_file(lines_symbolized.try_into()?);

        Ok(lines_symbolized)
    }
}
