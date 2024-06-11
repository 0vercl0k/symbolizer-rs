// Axel '0vercl0k' Souchet - February 20 2024
//! This module contains the implementation of the [`Symbolizer`] which is the
//! object that is able to symbolize files using PDB information if available.
use std::cell::RefCell;
use std::collections::{hash_map, HashMap};
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, Context};
use log::{debug, trace, warn};

use crate::addr_space::AddrSpace;
use crate::builder::{Builder, NoSymcache};
use crate::misc::{fast_hex32, fast_hex64};
use crate::modules::{Module, Modules};
use crate::pdbcache::{PdbCache, PdbCacheBuilder};
use crate::pe::{PdbId, Pe};
use crate::stats::{Stats, StatsBuilder};
use crate::{Error as E, Result};

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
            Err(e) => {
                return Err(E::DownloadPdb {
                    pdb_url,
                    e: e.into(),
                });
            }
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
    offline: bool,
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

    // If we're offline, let's just skip the downloading part.
    if offline {
        return Ok(None);
    }

    // We didn't find a PDB on disk, so last resort is to try to download it.
    let downloaded_path = try_download_from_guid(symsrvs, sympath, pdb_id)?;

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

#[derive(Debug, Default)]
pub enum PdbLookupMode {
    #[default]
    Offline,
    Online {
        /// List of symbol servers to try to download PDBs from when needed.
        symsrvs: Vec<String>,
    },
}

/// Configuration for the [`Symbolizer`].
#[derive(Debug)]
pub struct Config {
    /// Path to the local PDB symbol cache where PDBs will be
    /// downloaded into, or where we'll look for cached PDBs.
    pub symcache: PathBuf,
    /// This is the list of kernel / user modules read from the kernel crash
    /// dump.
    pub modules: Vec<Module>,
    /// Which mode are we using for PDB lookups? Online or Offline?
    pub mode: PdbLookupMode,
}

/// The [`Symbolizer`] is the main object that glues all the logic.
///
/// It downloads, parses PDB information, and symbolizes.
pub struct Symbolizer<'a, AS>
where
    AS: AddrSpace,
{
    /// Keep track of some statistics such as the number of lines symbolized,
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
    addr_space: RefCell<&'a mut AS>,
    /// List of symbol servers to try to download PDBs from when needed.
    symsrvs: Vec<String>,
    /// Caches addresses to symbols. This allows us to not have to symbolize an
    /// address again.
    addr_cache: RefCell<HashMap<u64, Rc<String>, IdentityHasher>>,
    /// Each parsed module is stored in this cache. We parse PDBs, etc. only
    /// once and then the [`PdbCache`] is used to query.
    pdb_caches: RefCell<HashMap<Range<u64>, Rc<PdbCache>>>,
    offline: bool,
}

impl<'a, AS> Symbolizer<'a, AS>
where
    AS: AddrSpace,
{
    pub fn builder() -> Builder<NoSymcache> {
        Builder::default()
    }

    /// Create a [`Symbolizer`].
    pub fn new(addr_space: &'a mut AS, config: Config) -> Result<Self> {
        let (offline, symsrvs) = match config.mode {
            PdbLookupMode::Offline =>
            // If the user wants offline, then let's do that..
            {
                (true, vec![])
            }
            PdbLookupMode::Online { symsrvs } => {
                // ..otherwise, we'll try to resolve a DNS and see what happens. If we can't do
                // that, then we'll assume we're offline and turn the offline mode.
                // Otherwise, we'll assume we have online access and attempt to download PDBs.
                let offline = ureq::get("https://www.google.com/").call().is_err();
                if offline {
                    debug!("Turning on 'offline' mode as you seem to not have internet access..");
                }

                (offline, symsrvs)
            }
        };

        if !config.symcache.is_dir() {
            return Err(anyhow!("{:?} directory does not exist", config.symcache))?;
        }

        Ok(Self {
            stats: Default::default(),
            symcache: config.symcache,
            modules: Modules::new(config.modules),
            addr_space: RefCell::new(addr_space),
            symsrvs,
            addr_cache: Default::default(),
            pdb_caches: Default::default(),
            offline,
        })
    }

    /// Get [`Stats`].
    pub fn stats(&self) -> Stats {
        self.stats.build()
    }

    /// Get the [`PdbCache`] for a specified `addr`.
    fn module_pdbcache(&self, addr: u64) -> Option<Rc<PdbCache>> {
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
    fn try_symbolize_addr_from_pdbs(&self, addr: u64) -> Result<Option<Rc<String>>> {
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
        let pe = Pe::new(*self.addr_space.borrow_mut(), module.at.start)?;

        // Ingest the EAT.
        builder.ingest(pe.exports.into_iter());

        // .. and see if it has PDB information.
        if let Some(pdb_id) = pe.pdb_id {
            trace!("Get PDB information for {module:?}/{pdb_id}..");

            // Try to get a PDB..
            let pdb_path = get_pdb(&self.symcache, &self.symsrvs, &pdb_id, self.offline)?;

            // .. and ingest it if we have one.
            if let Some((pdb_path, pdb_kind)) = pdb_path {
                if matches!(pdb_kind, PdbKind::Download) {
                    self.stats
                        .downloaded_file(pdb_id, pdb_path.metadata()?.len())
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
    fn try_symbolize_addr(&self, addr: u64) -> Result<Option<Rc<String>>> {
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
    pub fn modoff(&mut self, addr: u64, output: &mut impl Write) -> Result<()> {
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

        self.stats.addr_symbolized();

        Ok(())
    }

    /// Symbolize `addr` in the `module!function+offset` style and write the
    /// result into `output`.
    pub fn full(&mut self, addr: u64, output: &mut impl Write) -> Result<()> {
        match self.try_symbolize_addr(addr)? {
            Some(sym) => {
                output
                    .write_all(sym.as_bytes())
                    .context("failed to write symbolized value to output")?;

                self.stats.addr_symbolized();
                Ok(())
            }
            None => self.modoff(addr, output),
        }
    }
}
