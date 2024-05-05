// Axel '0vercl0k' Souchet - February 19 2024
//! This module contains the implementation of the PE parsing we do.
use std::fmt::Display;
use std::mem;
use std::ops::Range;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use kdmp_parser::{Gva, KdmpParserError, KernelDumpParser};
use log::debug;

use crate::guid::Guid;
use crate::misc::Rva;

/// The IMAGE_DOS_HEADER.
#[derive(Default, Debug)]
#[repr(C, packed(2))]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

/// The IMAGE_NT_HEADERS.
#[derive(Default, Debug)]
#[repr(C)]
struct NtHeaders {
    signature: u32,
    file_hdr: ImageFileHeader,
}

/// The IMAGE_FILE_HEADER.
#[derive(Default, Debug)]
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// The IMAGE_DATA_DIRECTORY.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// The IMAGE_OPTIONAL_HEADER32.
#[derive(Debug, Default)]
#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// The IMAGE_OPTIONAL_HEADER64.
#[derive(Debug, Default)]
#[repr(C, packed(4))]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// The IMAGE_DEBUG_DIRECTORY.
#[derive(Default, Debug)]
#[repr(C)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub type_: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// The IMAGE_EXPORT_DIRECTORY.
#[derive(Default, Debug)]
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// The code view information.
#[derive(Debug, Default)]
#[repr(C)]
pub struct Codeview {
    pub signature: u32,
    pub guid: [u8; 16],
    pub age: u32,
    // name follows
}

pub const IMAGE_NT_SIGNATURE: u32 = 17744;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 34404;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;

pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

/// A PDB identifier.
///
/// To download a PDB off Microsoft's Symbol Server, we need three pieces of
/// information: the pdb name, a guid and its age.
#[derive(Debug, Default)]
pub struct PdbId {
    pub path: PathBuf,
    pub guid: Guid,
    pub age: u32,
}

impl Display for PdbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}:{}:{:x}", self.path, self.guid, self.age))
    }
}

impl PdbId {
    pub fn new(path: PathBuf, guid: Guid, age: u32) -> Result<Self> {
        if path.file_name().is_none() {
            bail!("pdb path {path:?} does not have a filename");
        }

        Ok(Self { path, guid, age })
    }

    pub fn name(&self) -> String {
        self.path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
}

/// Calculate the absolute address of an array entry based on a base address,
/// the RVA of the array, the entry index and the size of an entry.
pub fn array_offset(base: u64, rva_array: u32, idx: u32, entry_size: usize) -> Option<u64> {
    let offset = idx.checked_mul(entry_size.try_into().ok()?)?;
    let rva = rva_array.checked_add(offset)?;

    base.checked_add(rva.into())
}

/// Read a NULL terminated string from the dump file at a specific address.
pub fn read_string(parser: &KernelDumpParser, addr: u64, max: usize) -> Result<String> {
    let mut s = String::new();
    let mut terminated = false;
    let mut gva = Gva::new(addr);
    for _ in 0..max {
        let mut buf = [0];
        parser
            .virt_read_exact(gva, &mut buf)
            .with_context(|| "failed reading null terminated string".to_string())?;

        let c = buf[0];
        if c == 0 {
            terminated = true;
            break;
        }

        s.push(c.into());
        gva += 1.into();
    }

    if !terminated && s.len() == max {
        s.push_str("...");
    }

    Ok(s)
}

/// A parsed PE headers.
///
/// We are only interested in the PDB identifier and the Export Address Table.
#[derive(Debug, Default)]
pub struct Pe {
    pub pdb_id: Option<PdbId>,
    pub exports: Vec<(Rva, String)>,
}

impl Pe {
    fn try_parse_debug_dir(
        parser: &KernelDumpParser,
        base: u64,
        opt_hdr: &ImageOptionalHeader64,
    ) -> Result<Option<PdbId>> {
        // Let's check if there's an ImageDebugDirectory.
        let debug_data_dir = opt_hdr.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if usize::try_from(debug_data_dir.size).unwrap() < mem::size_of::<ImageDebugDirectory>() {
            debug!("debug dir is too small");
            return Ok(None);
        }

        // Read it.
        let debug_dir_addr = base
            .checked_add(debug_data_dir.virtual_address.into())
            .ok_or_else(|| anyhow!("overflow with debug_data_dir"))?;
        let Some(debug_dir) =
            parser.try_virt_read_struct::<ImageDebugDirectory>(debug_dir_addr.into())?
        else {
            debug!(
                "failed to read ImageDebugDirectory {debug_dir_addr:#x} because of mem translation"
            );
            return Ok(None);
        };

        // If it's not a codeview type.. I don't know what to do, so let's bail.
        if debug_dir.type_ != IMAGE_DEBUG_TYPE_CODEVIEW {
            debug!("debug dir is not a codeview");
            return Ok(None);
        }

        // Let's make sure it's big enough to back a codeview structure.
        if usize::try_from(debug_dir.size_of_data).unwrap() < mem::size_of::<Codeview>() {
            debug!("codeview too small");
            return Ok(None);
        }

        // Let's read it.
        let codeview_addr = base
            .checked_add(debug_dir.address_of_raw_data.into())
            .ok_or_else(|| anyhow!("overflow with debug_dir"))?;
        let Some(codeview) = parser.try_virt_read_struct::<Codeview>(codeview_addr.into())? else {
            debug!("failed to read codeview {codeview_addr:#x} because of mem translation");
            return Ok(None);
        };

        // The codeview structure is followed by a NULL terminated string which is the
        // module name.
        let leftover =
            usize::try_from(debug_dir.size_of_data).unwrap() - mem::size_of::<Codeview>();
        if leftover == 0 || leftover > 256 {
            bail!("the module path is either 0 or larger than reasonable");
        }

        // Allocate space for it, and read it.
        let mut file_name = vec![0; leftover];
        let file_name_addr = array_offset(
            base,
            debug_dir.address_of_raw_data,
            1,
            mem::size_of::<Codeview>(),
        )
        .ok_or_else(|| anyhow!("oveflow with debug_dir"))?;

        let Some(amount) = parser.try_virt_read(file_name_addr.into(), &mut file_name)? else {
            return Ok(None);
        };

        // The last character is supposed to be a NULL byte, bail if it's not there.
        if *file_name.last().unwrap() != 0 {
            bail!("the module path doesn't end with a NULL byte");
        }

        file_name.resize(amount - 1, 0);

        // All right, at this point we have everything we need: the PDB name / GUID /
        // age. Those are the three piece of information we need to download a PDB
        // off Microsoft's symbol server.
        let path = PathBuf::from(String::from_utf8(file_name)?);

        Ok(Some(PdbId::new(path, codeview.guid.into(), codeview.age)?))
    }

    fn try_parse_export_dir(
        parser: &KernelDumpParser,
        base: u64,
        opt_hdr: &ImageOptionalHeader64,
    ) -> Result<Option<Vec<(Rva, String)>>> {
        // Let's check if there's an EAT.
        debug!("parsing EAT..");
        let export_data_dir = opt_hdr.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if usize::try_from(export_data_dir.size)? < mem::size_of::<ImageExportDirectory>() {
            debug!("export dir is too small");
            return Ok(None);
        }

        // Read it.
        let export_dir_addr = base
            .checked_add(u64::from(export_data_dir.virtual_address))
            .ok_or_else(|| anyhow!("overflow with export_data_dir"))?;
        let Some(export_dir) =
            parser.try_virt_read_struct::<ImageExportDirectory>(export_dir_addr.into())?
        else {
            debug!("failed to read ImageExportDirectory {export_dir_addr:#x} because of mem translation");
            return Ok(None);
        };

        // Read the ordinal / name arrays.
        // """
        // The export name pointer table is an array of addresses (RVAs) into the export
        // name table. The pointers are 32 bits each and are relative to the image base.
        // The pointers are ordered lexically to allow binary searches.
        // An export name is defined only if the export name pointer table contains a
        // pointer to it. """
        let n_names = export_dir.number_of_names;
        let addr_of_names = export_dir.address_of_names;
        // """
        // The export ordinal table is an array of 16-bit unbiased indexes into the
        // export address table. Ordinals are biased by the Ordinal Base field of the
        // export directory table. In other words, the ordinal base must be subtracted
        // from the ordinals to obtain true indexes into the export address table.
        // """
        let addr_of_ords = export_dir.address_of_name_ordinals;
        let mut names = Vec::with_capacity(n_names.try_into()?);
        let mut ords = Vec::with_capacity(names.len());
        for name_idx in 0..n_names {
            // Read the name RVA's..
            let name_rva_addr = array_offset(base, addr_of_names, name_idx, mem::size_of::<u32>())
                .ok_or_else(|| anyhow!("overflow with name_rva_addr"))?;
            let Some(name_rva) = parser
                .try_virt_read_struct::<u32>(name_rva_addr.into())
                .with_context(|| "failed to read EAT's name array".to_string())?
            else {
                debug!(
                    "failed to read EAT's name array {name_rva_addr:#x} because of mem translation"
                );
                return Ok(None);
            };

            let name_addr = base
                .checked_add(name_rva.into())
                .ok_or_else(|| anyhow!("overflow with name_addr"))?;
            // ..then read the string in memory.
            let name = read_string(parser, name_addr, 64)?;
            names.push(name);

            // Read the ordinal.
            let ord_addr = array_offset(base, addr_of_ords, name_idx, mem::size_of::<u16>())
                .ok_or_else(|| anyhow!("overflow with ord_addr"))?;
            let Some(ord) = parser
                .try_virt_read_struct::<u16>(ord_addr.into())
                .with_context(|| "failed to read EAT's ord array".to_string())?
            else {
                debug!("failed to read EAT's ord array {ord_addr:#x} because of mem translation");
                return Ok(None);
            };
            ords.push(ord);
        }

        debug!("read {n_names} names");

        // Read the address array.
        //
        // """
        // The export address table contains the address of exported entry points and
        // exported data and absolutes. An ordinal number is used as an index into the
        // export address table.
        // """
        let addr_of_functs = export_dir.address_of_functions;
        let n_functs = export_dir.number_of_functions;
        let mut address_rvas = Vec::with_capacity(n_functs.try_into()?);
        for addr_idx in 0..n_functs {
            // Read the RVA.
            let address_rva_addr =
                array_offset(base, addr_of_functs, addr_idx, mem::size_of::<u32>())
                    .ok_or_else(|| anyhow!("overflow with address_rva_addr"))?;

            let Some(address_rva) = parser
                .try_virt_read_struct::<u32>(address_rva_addr.into())
                .with_context(|| "failed to read EAT's address array".to_string())?
            else {
                debug!("failed to read EAT's address array {address_rva_addr:#x} because of mem translation");
                return Ok(None);
            };

            address_rvas.push(address_rva);
        }

        debug!("read {n_functs} addresses");

        // Time to build the EAT.
        let eat_range = Range {
            start: export_data_dir.virtual_address,
            end: export_data_dir
                .virtual_address
                .checked_add(export_data_dir.size)
                .ok_or_else(|| anyhow!("overflow with export data dir size"))?,
        };

        let mut exports = Vec::with_capacity(address_rvas.len());
        for (unbiased_ordinal, addr_rva) in address_rvas.drain(..).enumerate() {
            let ordinal = unbiased_ordinal
                .checked_add(export_dir.base.try_into()?)
                .ok_or_else(|| anyhow!("overflow with biased_ordinal"))?;
            let name = ords
                .iter()
                .position(|&o| usize::from(o) == unbiased_ordinal)
                .map(|name_idx| names[name_idx].clone())
                .unwrap_or_else(|| format!("ORD#{ordinal}"));

            let forwarder = eat_range.contains(&addr_rva);
            if !forwarder {
                exports.push((addr_rva, name.clone()));
            }
        }

        debug!("built table w/ {} entries", exports.len());

        Ok(Some(exports))
    }

    pub fn new(parser: &KernelDumpParser, base: u64) -> Result<Self> {
        // All right let's parse the PE.
        debug!("parsing PE @ {:#x}", base);

        // Read the DOS/NT headers.
        let dos_hdr = parser
            .virt_read_struct::<ImageDosHeader>(base.into())
            .with_context(|| "failed to read ImageDosHeader")?;
        let nt_hdr_addr = base
            .checked_add(dos_hdr.e_lfanew.try_into().unwrap())
            .ok_or_else(|| anyhow!("overflow with e_lfanew"))?;
        let nt_hdr = parser.virt_read_struct::<NtHeaders>(nt_hdr_addr.into())?;

        // Let's verify the signature..
        if nt_hdr.signature != IMAGE_NT_SIGNATURE {
            bail!("wrong PE signature for {base:#x}");
        }

        // ..and let's ignore non x64 PEs.
        if nt_hdr.file_hdr.machine != IMAGE_FILE_MACHINE_AMD64 {
            bail!("wrong architecture for {base:#x}");
        }

        // Now locate the optional header, and check that it looks big enough.
        let opt_hdr_addr = nt_hdr_addr
            .checked_add(mem::size_of_val(&nt_hdr).try_into().unwrap())
            .ok_or_else(|| anyhow!("overflow with nt_hdr"))?;
        let opt_hdr_size = nt_hdr.file_hdr.size_of_optional_header as usize;
        debug!("parsing optional hdr @ {:#x}", opt_hdr_addr);

        // If it's not big enough, let's bail.
        if opt_hdr_size < mem::size_of::<ImageOptionalHeader64>() {
            bail!("optional header's size is too small");
        }

        // Read the IMAGE_OPTIONAL_HEADER64.
        let opt_hdr = parser
            .virt_read_struct::<ImageOptionalHeader64>(opt_hdr_addr.into())
            .with_context(|| "failed to read ImageOptionalHeader64")?;

        // Read the PDB information if there's any.
        let pdb_id = Self::try_parse_debug_dir(parser, base, &opt_hdr)?;

        // Read the EXPORT table if there's any.
        let exports = match Self::try_parse_export_dir(parser, base, &opt_hdr) {
            Ok(o) => o,
            Err(e) => {
                let Some(kdmp) = e.downcast_ref::<KdmpParserError>() else {
                    return Err(e);
                };

                match kdmp {
                    KdmpParserError::AddrTranslation(..) => None,
                    _ => return Err(e),
                }
            }
        }
        .unwrap_or_default();

        Ok(Self { pdb_id, exports })
    }
}
