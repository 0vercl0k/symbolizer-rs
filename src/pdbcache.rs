// Axel '0vercl0k' Souchet - February 23 2024
//! This module contains the implementation of the [`PdbCache`] which is the
//! object that keeps track of all the information needed to symbolize an
//! address. It extracts it out of a PDB file and doesn't require it to be
//! around.
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Range;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use log::{trace, warn};
use pdb::{
    AddressMap, FallibleIterator, LineProgram, PdbInternalSectionOffset, ProcedureSymbol,
    StringTable, Symbol,
};

use crate::modules::Module;

/// A PDB opened via file access.
type Pdb<'p> = pdb::PDB<'p, File>;
/// A relative virtual address.
type Rva = u32;
/// A vector of lines.
type Lines = Vec<Line>;

/// A line of source code.
///
/// It maps an offset in the function (like offset
/// `0x1122`) to a line number in a file (like `foo.c:1336`).
#[derive(Default, Debug)]
struct Line {
    /// Offset from the start of the function it's part of.
    offset: u32,
    /// The line number.
    number: Rva,
    /// Most lines in a function are part of the same file which is stored in
    /// the [`SourceInfo`] which contains the lines info. But in case, this line
    /// is stored in a different file, this is its path.
    override_path: Option<String>,
}

impl Line {
    /// Build a [`Line`].
    fn new(offset: Rva, number: u32, override_path: Option<String>) -> Self {
        Self {
            offset,
            number,
            override_path,
        }
    }
}

/// Information related to source code.
///
/// It contains the path to the source code file as well as a mapping between
/// offsets to line number.
#[derive(Debug, Default)]
struct SourceInfo {
    path: String,
    lines: Lines,
}

impl SourceInfo {
    /// Build a [`SourceInfo`].
    fn new(path: String, lines: Lines) -> Self {
        // We assume we have at least one entry in the vector.
        assert!(!lines.is_empty());

        Self { path, lines }
    }

    /// Find the line number associated to a raw offset from inside a function.
    pub fn line(&self, offset: Rva) -> &Line {
        self.lines
            .iter()
            .find(|&line| offset < line.offset)
            .unwrap_or(self.lines.last().unwrap())
    }
}

/// A function.
///
/// It has a name and if available, information related to the file where the
/// function is implemented as well as the line of code.
#[derive(Default, Debug)]
struct FuncSymbol {
    pub name: String,
    pub source_info: Option<SourceInfo>,
}

impl FuncSymbol {
    fn new(name: String, source_info: Option<SourceInfo>) -> Self {
        Self { name, source_info }
    }
}

impl From<BuilderEntry> for FuncSymbol {
    fn from(value: BuilderEntry) -> Self {
        FuncSymbol::new(value.name, value.source_info)
    }
}

/// A PDB cache.
///
/// It basically is a data-structure that stores all the information about the
/// functions defined in a module. It extracts everything it can off a PDB and
/// then toss it as a PDB file is larger than a [`PdbCache`] (as we don't care
/// about types, variables, etc.).
pub struct PdbCache {
    module_name: String,
    addrs: Vec<Range<Rva>>,
    symbols: Vec<FuncSymbol>,
}

impl Debug for PdbCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdbCache")
            .field("module_name", &self.module_name)
            .finish_non_exhaustive()
    }
}

impl PdbCache {
    fn new(module_name: String, mut symbols: Vec<(Range<Rva>, FuncSymbol)>) -> Self {
        symbols.sort_unstable_by_key(|(range, _)| range.end);
        let (addrs, symbols) = symbols.into_iter().unzip();

        Self {
            module_name,
            addrs,
            symbols,
        }
    }

    /// Find a symbol that contains `rva`.
    fn find_sym(&self, rva: Rva) -> Option<(Rva, &FuncSymbol)> {
        let idx = self.addrs.partition_point(|probe| probe.end <= rva);
        if idx == self.addrs.len() {
            return None;
        }

        let range = &self.addrs[idx];
        let func = &self.symbols[idx];

        if range.contains(&rva) {
            Some((range.start, func))
        } else {
            None
        }
    }

    /// Symbolize a raw address.
    ///
    /// This pulls as much information as possible and use any private symbols
    /// if there were any.
    pub fn symbolize(&self, rva: Rva) -> Result<String> {
        // Find the function in which this `rva` is in.
        let Some((func_rva, func_symbol)) = self.find_sym(rva) else {
            // If we can't find one, we'll just return `module.dll+rva`.
            return Ok(format!("{}+{:#x}", self.module_name, rva));
        };

        debug_assert!(
            rva >= func_rva,
            "The function RVA should always be smaller or equal to the instruction RVA"
        );

        // Calculate the instruction offset.
        let instr_offset = rva - func_rva;

        // Generate the symbolized version.
        let symbolized = if let Some(source_info) = &func_symbol.source_info {
            // If we have knowledge about in which source file this is implemented and at
            // what line number, then let's use it..
            let line = source_info.line(instr_offset);
            let path = line.override_path.as_ref().unwrap_or(&source_info.path);

            format!(
                "{}!{}+{instr_offset:#x} [{path} @ {}]",
                self.module_name, func_symbol.name, line.number
            )
        } else {
            // ..or do without if it's not present.
            format!(
                "{}!{}+{instr_offset:#x}",
                self.module_name, func_symbol.name
            )
        };

        Ok(symbolized)
    }
}

#[derive(Debug)]
struct BuilderEntry {
    name: String,
    len: Option<u32>,
    source_info: Option<SourceInfo>,
}

impl BuilderEntry {
    fn new(name: String, len: Option<u32>, source_info: Option<SourceInfo>) -> Self {
        Self {
            name,
            len,
            source_info,
        }
    }

    fn with_name(name: String) -> Self {
        Self::new(name, None, None)
    }

    fn len(&self) -> Option<u32> {
        self.len
    }
}

/// A [`PdbCache`] builder.
///
/// Ultimately, we try to get as much information possible on modules with what
/// we have. Sometimes, we have public symbols, something we have private
/// symbols and.. sometimes we have nothing (just its PE). If we're dealing with
/// just information extracted from the PE or the public symbols, we have no
/// available information regarding function sizes.
///
/// To work around this issue, what we do is we aggregate all the information in
/// a data structure ordered by the function address. Once we're done, we walk
/// this data structure and we calculate the size of the current function by
/// 'filling the hole' up to the next function. This is innacurate but is the
/// only heuristic I had in store.
///
/// Once we have a list of functions with assigned sizes, we can finally build
/// the [`PdbCache`] structure.
#[derive(Debug)]
pub struct PdbCacheBuilder<'module> {
    /// The module for which this symbol cache is for.
    module: &'module Module,
    /// Basically all the information we've extracted so far.
    ///
    /// The key is the [`Rva`] of where the module starts, and the value is a
    /// [`BuilderEntry`] which describes the symbol with more details.
    symbols: BTreeMap<Rva, BuilderEntry>,
}

impl<'module> PdbCacheBuilder<'module> {
    pub fn new(module: &'module Module) -> Self {
        Self {
            module,
            symbols: BTreeMap::new(),
        }
    }

    /// Ingest a bunch of symbols.
    ///
    /// The key is the start [`Rva`] of the symbol, and the value is its name.
    /// This is used to ingest for example a list of functions acquired from the
    /// EAT of a module.
    pub fn ingest(&mut self, symbols: impl Iterator<Item = (Rva, String)>) {
        for (start, name) in symbols {
            self.symbols.insert(start, BuilderEntry::with_name(name));
        }
    }

    /// Parse a [`ProcedureSymbol`].
    fn parse_procedure_symbol(
        &mut self,
        proc: &ProcedureSymbol,
        address_map: &AddressMap,
        string_table: &StringTable,
        line_program: &LineProgram,
    ) -> Result<()> {
        let proc_name = proc.name.to_string();
        let Some(pdb::Rva(proc_rva)) = proc.offset.to_rva(address_map) else {
            warn!(
                "failed to get rva for procedure symbol {} / {:?}, skipping",
                proc_name, proc.offset
            );

            return Ok(());
        };

        let mut lines_it = line_program.lines_for_symbol(proc.offset);
        let mut main_path = None;
        let mut lines = Lines::new();
        while let Some(line) = lines_it.next()? {
            let Some(pdb::Rva(line_rva)) = line.offset.to_rva(address_map) else {
                warn!(
                    "failed to get rva for procedure symbol {} / {:?}, skipping",
                    proc_name, proc.offset
                );
                continue;
            };

            let file_info = line_program.get_file_info(line.file_index)?;
            let override_path = if main_path.is_none() {
                main_path = Some(file_info.name.to_string_lossy(string_table)?.into_owned());

                None
            } else {
                let new_path = file_info.name.to_string_lossy(string_table)?;
                if main_path.as_ref().unwrap() != &new_path {
                    Some(new_path.into_owned())
                } else {
                    None
                }
            };

            if line_rva < proc_rva {
                warn!(
                    "symbol {} has confusing line information, skipping",
                    proc_name
                );
                return Ok(());
            }

            let line_offset = line_rva - proc_rva;
            lines.push(Line::new(line_offset, line.line_start, override_path));
        }

        self.ingest_symbol(
            address_map,
            proc_name,
            proc.offset,
            Some(proc.len),
            main_path.map(|p| SourceInfo::new(p, lines)),
        )
    }

    /// Ingest a symbol with a name.
    fn ingest_symbol_with_name(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
    ) -> Result<()> {
        self.ingest_symbol(address_map, name, offset, None, None)
    }

    /// Ingest a symbol with a name and a length.
    fn ingest_symbol_with_len(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
        len: u32,
    ) -> Result<()> {
        self.ingest_symbol(address_map, name, offset, Some(len), None)
    }

    /// Ingest a symbol.
    ///
    /// Some symbols have a length, some don't, some have source information,
    /// some don't.
    fn ingest_symbol(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
        len: Option<u32>,
        source_info: Option<SourceInfo>,
    ) -> Result<()> {
        use msvc_demangler::DemangleFlags as E;
        let undecorated_name = if name.as_bytes().starts_with(b"?") {
            // Demangle the name if it starts by a '?'.
            match msvc_demangler::demangle(&name, E::NAME_ONLY) {
                Ok(o) => o,
                Err(e) => {
                    // Let's log the failures as warning because we might care one day?
                    warn!("failed to demangle {name}: {e}");

                    // But if it failed, returning the mangled name is better than nothing.
                    name.into_owned()
                }
            }
        } else {
            // If it isn't a mangled name, then do.. nothing!
            name.into()
        };

        // Get the RVA..
        let pdb::Rva(rva) = offset.to_rva(address_map).ok_or_else(|| {
            anyhow!(
                "failed to get rva from symbol {undecorated_name} / {:?}, skipping",
                offset
            )
        })?;

        //.. and build an entry for this function.
        if let Some(prev) = self
            .symbols
            .insert(rva, BuilderEntry::new(undecorated_name, len, source_info))
        {
            warn!("symbol {prev:?} in dbi has a duplicate at {rva:#x}, skipping");
        }

        Ok(())
    }

    /// Parse a [`Symbol`].
    fn parse_symbol(
        &mut self,
        address_map: &AddressMap,
        symbol: &Symbol,
        extra: Option<(&StringTable, &LineProgram)>,
    ) -> Result<()> {
        use pdb::SymbolData as SD;
        match symbol.parse()? {
            SD::Procedure(procedure) => {
                let (string_table, line_program) = extra.unwrap();
                self.parse_procedure_symbol(&procedure, address_map, string_table, line_program)?;
            }
            SD::Public(public) => {
                self.ingest_symbol_with_name(address_map, public.name.to_string(), public.offset)?;
            }
            SD::Thunk(thunk) => {
                self.ingest_symbol_with_len(
                    address_map,
                    thunk.name.to_string(),
                    thunk.offset,
                    thunk.len.into(),
                )?;
            }
            _ => {}
        };

        Ok(())
    }

    /// Parse the debug information stream which is where private symbols are
    /// stored in.
    fn parse_dbi(&mut self, pdb: &mut Pdb, address_map: &AddressMap) -> Result<()> {
        // If we don't have a string table, there is no point in parsing the debug
        // information stream.
        let Ok(string_table) = pdb.string_table() else {
            return Ok(());
        };

        // Grab the debug information stream..
        let dbi = pdb.debug_information().context("failed to get dbi")?;
        // ..and grab / walk through the 'modules'.
        let mut module_it = dbi.modules()?;
        while let Some(module) = module_it.next()? {
            // Get information about the module; such as its path, its symbols, etc.
            let Some(info) = pdb.module_info(&module)? else {
                warn!("no module info: {:?}", &module);
                continue;
            };

            let program = info.line_program()?;
            let mut sym_it = info.symbols()?;
            while let Some(symbol) = sym_it.next()? {
                if let Err(e) =
                    self.parse_symbol(address_map, &symbol, Some((&string_table, &program)))
                {
                    warn!("parsing {symbol:?} failed with {e:?}, ignoring");
                }
            }
        }

        Ok(())
    }

    /// Parse the global symbols stream where public symbols are stored at.
    fn parse_global_symbols_table(
        &mut self,
        pdb: &mut Pdb,
        address_map: &AddressMap,
    ) -> Result<()> {
        let global_symbols = pdb.global_symbols()?;
        let mut symbol_it = global_symbols.iter();
        while let Some(symbol) = symbol_it.next()? {
            if let Err(e) = self.parse_symbol(address_map, &symbol, None) {
                warn!("parsing {symbol:?} failed with {e:?}, ignoring");
            }
        }

        Ok(())
    }

    /// Ingest a PDB file stored on the file system.
    pub fn ingest_pdb(&mut self, pdb_path: impl AsRef<Path>) -> Result<()> {
        // Open the PDB file.
        let pdb_path = pdb_path.as_ref();
        let pdb_file =
            File::open(pdb_path).with_context(|| format!("failed to open pdb {pdb_path:?}"))?;
        let mut pdb =
            Pdb::open(pdb_file).with_context(|| format!("failed to parse pdb {pdb_path:?}"))?;

        trace!("ingesting {pdb_path:?}..");

        let address_map = pdb.address_map()?;
        // Parse and extract all the bits we need from the private symbols first. We do
        // this first, because procedures have a length field which isn't the case for
        // global symbols. And if there's duplicates, then we'd rather have the entry
        // that gives us the exact procedure length instead of us guessing.
        self.parse_dbi(&mut pdb, &address_map)
            .context("failed to parse private symbols")?;

        // Parse and extract all the bits we need from the global symbols..
        self.parse_global_symbols_table(&mut pdb, &address_map)
            .context("failed to parse public symbols")
    }

    /// Build a [`PdbCache`].
    pub fn build(mut self) -> Result<PdbCache> {
        // Walk the map of ordered RVA with their associated names and assign lengths to
        // each of the functions. Some function have a length and some don't. If a
        // length is specified, then we'll use it; otherwise we'll assign one ourselves.
        let mut functions = Vec::with_capacity(self.symbols.len());
        while let Some((start, entry)) = self.symbols.pop_first() {
            let end = if let Some(len) = entry.len() {
                // If we have a length, then use it!
                start
                    .checked_add(len)
                    .ok_or_else(|| anyhow!("overflow w/ symbol range"))?
            } else {
                // If we don't have one, the length of the current function is basically up to
                // the next entry.
                //
                // For example imagine the below:
                //  - RVA: 0, Name: foo
                //  - RVA: 5, Name: bar
                //
                // In that case, we consider the first function to be spanning [0..4], and
                // [5..module size] for the second one.

                // If we didn't pop the last value, then just check the one that follows.
                if let Some((&end, _)) = self.symbols.first_key_value() {
                    end
                } else {
                    debug_assert!(self.module.at.end > self.module.at.start);

                    // If we popped the last value, just use the module end as the end of the range.
                    u32::try_from(self.module.at.end - self.module.at.start)
                        .context("failed to make the module's end into a rva")?
                }
            };

            functions.push((Range { start, end }, entry.into()));
        }

        Ok(PdbCache::new(self.module.name.clone(), functions))
    }
}
