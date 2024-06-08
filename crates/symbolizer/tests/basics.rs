// Axel '0vercl0k' Souchet - May 30 2024
use std::env::temp_dir;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use object::read::pe::PeFile64;
use object::{NativeEndian, ReadCache, ReadRef};
use symbolizer::{AddrSpace, Builder, Module};

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
fn raw_virt() {
    let raw_addr_space = RawAddressSpace::new(&fixture("mrt100.raw")).unwrap();
    let len = raw_addr_space.len();

    let mut symb = Builder::default()
        .modules(vec![Module::new("mrt100", 0x0, len)].into_iter())
        .online(vec!["https://msdl.microsoft.com/download/symbols/"].into_iter())
        .symcache(&symcache("basics"))
        .build(raw_addr_space)
        .unwrap();

    for (addr, expected_full, expected_modoff) in EXPECTED_RAW {
        let mut full = Vec::new();
        symb.full(addr, &mut full).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), expected_full);

        let mut modoff = Vec::new();
        symb.modoff(addr, &mut modoff).unwrap();
        assert_eq!(String::from_utf8(modoff).unwrap(), expected_modoff);
    }

    assert_eq!(symb.stats().n_downloads, 1);
}

#[test]
fn raw_file() {
    let file = File::open(fixture("mrt100.dll")).unwrap();
    let cache = ReadCache::new(file);
    let file_addr_space = FileAddressSpace::new(&cache).unwrap();
    let len = file_addr_space.len();

    let mut symb = Builder::default()
        .modules(vec![Module::new("mrt100", 0x0, len)].into_iter())
        .online(vec!["https://msdl.microsoft.com/download/symbols/"].into_iter())
        .symcache(&symcache("basics"))
        .build(file_addr_space)
        .unwrap();

    for (addr, expected_full, expected_modoff) in EXPECTED_RAW {
        let mut full = Vec::new();
        symb.full(addr, &mut full).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), expected_full);

        let mut modoff = Vec::new();
        symb.modoff(addr, &mut modoff).unwrap();
        assert_eq!(String::from_utf8(modoff).unwrap(), expected_modoff);
    }

    assert_eq!(symb.stats().n_downloads, 1);
}
