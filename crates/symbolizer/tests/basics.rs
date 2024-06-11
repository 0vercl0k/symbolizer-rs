// Axel '0vercl0k' Souchet - May 30 2024
use std::cmp::min;
use std::env::temp_dir;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use object::read::pe::PeFile64;
use object::{NativeEndian, ReadCache, ReadRef};
use symbolizer::{AddrSpace, Builder, Guid, Module, PdbId};
use udmp_parser::UserDumpParser;

const EXPECTED_LEN: u64 = 0x90_00;
const EXPECTED_RAW: [(u64, &str, &str); 4] = [
    (
        0x19_50,
        "mrt100!GetManagedRuntimeService+0x0",
        "mrt100+0x00001950",
    ),
    (
        0x19_30,
        "mrt100!ManagedRuntimeServices::SetWerDataBuffer+0x0",
        "mrt100+0x00001930",
    ),
    (EXPECTED_LEN, "0x0000000000009000", "0x0000000000009000"),
    (0xdeadbeef, "0x00000000deadbeef", "0x00000000deadbeef"),
];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(&env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn symcache(name: &str) -> PathBuf {
    let cache = temp_dir().join(name);
    let _ = fs::remove_dir_all(&cache);
    let _ = fs::create_dir(&cache);

    cache
}

#[derive(Debug)]
struct RawAddressSpace {
    raw: File,
    len: u64,
}

impl RawAddressSpace {
    fn new(path: &impl AsRef<Path>) -> io::Result<Self> {
        let raw = File::open(path)?;
        let metadata = raw.metadata()?;
        let len = metadata.len();

        Ok(Self { raw, len })
    }

    fn len(&self) -> u64 {
        self.len
    }
}

impl AddrSpace for RawAddressSpace {
    fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        Seek::seek(&mut self.raw, io::SeekFrom::Start(addr))?;

        Read::read(&mut self.raw, buf)
    }

    fn try_read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        self.read_at(addr, buf).map(Some)
    }
}

#[test]
fn raw_virt() {
    let mut raw_addr_space = RawAddressSpace::new(&fixture("mrt100.raw")).unwrap();
    let len = raw_addr_space.len();

    let mut symb = Builder::default()
        .modules(&vec![Module::new("mrt100", 0x0, len)])
        .msft_symsrv()
        .symcache(&symcache("basics"))
        .build(&mut raw_addr_space)
        .unwrap();

    for (addr, expected_full, expected_modoff) in EXPECTED_RAW {
        let mut full = Vec::new();
        symb.full(addr, &mut full).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), expected_full);

        let mut modoff = Vec::new();
        symb.modoff(addr, &mut modoff).unwrap();
        assert_eq!(String::from_utf8(modoff).unwrap(), expected_modoff);
    }

    let stats = symb.stats();
    assert_eq!(stats.amount_pdb_downloaded(), 1);
    assert!(stats.did_download(
        PdbId::new(
            "mrt100.pdb",
            "A20DA44BF08DB27D2BA0928F79447C7D".try_into().unwrap(),
            1
        )
        .unwrap()
    ));
}

#[derive(Debug)]
struct FileAddressSpace<'data> {
    pe: PeFile64<'data, &'data ReadCache<File>>,
    virt_len: u64,
}

impl<'data> FileAddressSpace<'data> {
    fn new(cache: &'data ReadCache<File>) -> io::Result<Self> {
        let pe =
            PeFile64::parse(cache).map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;

        let virt_len = pe
            .nt_headers()
            .optional_header
            .size_of_image
            .get(NativeEndian)
            .into();

        Ok(Self { pe, virt_len })
    }

    fn len(&self) -> u64 {
        self.virt_len
    }
}

impl<'data> AddrSpace for FileAddressSpace<'data> {
    fn read_at(&mut self, addr: u64, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if addr >= self.virt_len {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{addr:#x} vs {:#x} is oob", self.virt_len),
            ));
        }

        let data = match self
            .pe
            .section_table()
            .pe_data_at(self.pe.data(), addr.try_into().unwrap())
        {
            Some(data) => data,
            None => self
                .pe
                .data()
                .read_slice_at(addr, buf.len())
                .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "read_slice_at"))?,
        };

        buf.write(data)
    }

    fn try_read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        self.read_at(addr, buf).map(Some)
    }
}

#[test]
fn raw_file() {
    let file = File::open(fixture("mrt100.dll")).unwrap();
    let cache = ReadCache::new(file);
    let mut file_addr_space = FileAddressSpace::new(&cache).unwrap();
    let len = file_addr_space.len();

    let mut symb = Builder::default()
        .modules(&vec![Module::new("mrt100", 0x0, len)])
        .online(vec!["https://msdl.microsoft.com/download/symbols/"].into_iter())
        .symcache(&symcache("basics"))
        .build(&mut file_addr_space)
        .unwrap();

    for (addr, expected_full, expected_modoff) in EXPECTED_RAW {
        let mut full = Vec::new();
        symb.full(addr, &mut full).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), expected_full);

        let mut modoff = Vec::new();
        symb.modoff(addr, &mut modoff).unwrap();
        assert_eq!(String::from_utf8(modoff).unwrap(), expected_modoff);
    }

    let stats = symb.stats();
    assert_eq!(stats.amount_pdb_downloaded(), 1);
    assert!(stats.did_download(
        PdbId::new(
            "mrt100.pdb",
            "A20DA44BF08DB27D2BA0928F79447C7D".try_into().unwrap(),
            1
        )
        .unwrap()
    ));
}

#[derive(Debug)]
struct UserDumpAddrSpace<'a>(UserDumpParser<'a>);

impl<'a> AddrSpace for UserDumpAddrSpace<'a> {
    fn read_at(&mut self, addr: u64, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut cur_addr = addr;
        let mut read_len = 0;
        while read_len < buf.len() {
            let Some(block) = self.0.get_mem_block(addr) else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("no mem block found for {addr:#x}"),
                ));
            };

            let Some(data) = block.data_from(cur_addr) else {
                panic!();
            };

            let left = buf.len() - read_len;
            let len = min(data.len(), left);
            buf.write(&data[..len]).unwrap();
            cur_addr += u64::try_from(len).unwrap();
            read_len += len;
        }

        Ok(read_len)
    }

    fn try_read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.read_at(addr, buf) {
            Ok(sz) => Ok(Some(sz)),
            Err(_) => Ok(None),
        }
    }
}

#[test]
fn user_dump() {
    let dump = UserDumpParser::new(fixture("udmp.dmp")).unwrap();
    let modules = dump
        .modules()
        .values()
        .map(|module| {
            Module::new(
                module.path.file_name().unwrap().to_string_lossy(),
                module.start_addr(),
                module.end_addr(),
            )
        })
        .collect::<Vec<_>>();

    let mut udmp_addr_space = UserDumpAddrSpace(dump);
    let mut symb = Builder::default()
        .modules(&modules)
        .msft_symsrv()
        .symcache(&symcache("basics"))
        .build(&mut udmp_addr_space)
        .unwrap();

    // 0:000> u 00007ff9`aa4f8eb2
    // ntdll!EvtIntReportEventWorker$fin$0+0x2:
    // 00007ff9`aa4f8eb2 4883ec50        sub     rsp,50h
    let mut output = Vec::new();
    symb.full(0x7ff9aa4f8eb2, &mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "ntdll.dll!EvtIntReportEventWorker$fin$0+0x2"
    );

    let stats = symb.stats();
    assert_eq!(stats.amount_pdb_downloaded(), 1);
    assert!(stats.did_download(
        PdbId::new(
            "ntdll.pdb",
            "8D5D5ED5D5B8AA609A82600C14E3004D".try_into().unwrap(),
            1
        )
        .unwrap()
    ));

    drop(symb);
    let mut symb_offline = Builder::default()
        .symcache(&symcache("basics"))
        .modules(&modules)
        .build(&mut udmp_addr_space)
        .unwrap();

    // 0:000> u 00007ff9`aa4f8eb2
    // ntdll!EvtIntReportEventWorker$fin$0+0x2:
    // 00007ff9`aa4f8eb2 4883ec50        sub     rsp,50h
    let mut output = Vec::new();
    symb_offline.full(0x7ff9aa4f8eb2, &mut output).unwrap();
    assert_ne!(
        String::from_utf8(output).unwrap(),
        "ntdll.dll!EvtIntReportEventWorker$fin$0+0x2"
    );

    let stats = symb_offline.stats();
    assert_eq!(stats.amount_pdb_downloaded(), 0);
}
