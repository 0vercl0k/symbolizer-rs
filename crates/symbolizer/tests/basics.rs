// Axel '0vercl0k' Souchet - May 30 2024
use std::io::{self, Read, Seek};
use std::path::Path;
use std::{env::temp_dir, fs::File};

use symbolizer::{AddressSpace, Module, Symbolizer};

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

impl AddressSpace for RawAddressSpace {
    fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.raw.seek(io::SeekFrom::Start(addr))?;

        self.raw.read(buf)
    }

    fn try_read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        self.read_at(addr, buf).map(Some)
    }
}

#[test]
fn foo() {
    let symcache = temp_dir().join("basics");
    let raw = RawAddressSpace::new(&r"c:\work\mrt100.raw").unwrap();
    let modules = vec![Module::new("mrt100", 0x0, raw.len())];

    let mut symb = Symbolizer::new(symcache, vec![], modules, raw);

    let mut buf = Vec::new();
    symb.full(&mut buf, 0x19_50).unwrap();
    assert_eq!(
        String::from_utf8(buf).unwrap().trim_end(),
        "mrt100!GetManagedRuntimeService+0x0"
    );
}
