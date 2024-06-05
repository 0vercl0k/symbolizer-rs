// Axel '0vercl0k' Souchet - May 30 2024
use std::env::temp_dir;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::Path;

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
fn raw() {
    let symcache = temp_dir().join("basics");
    let raw = RawAddressSpace::new(&r"c:\work\mrt100.raw").unwrap();
    let raw_len = raw.len();
    let modules = vec![Module::new("mrt100", 0x0, raw_len)];

    let mut symb = Symbolizer::new(symcache, vec![], modules, raw);

    let expected = [
        (
            0x19_50,
            "mrt100!GetManagedRuntimeService+0x0",
            "mrt100+0x00001950",
        ),
        (raw_len, "0x0000000000009000", "0x0000000000009000"),
        (0xdeadbeef, "0x00000000deadbeef", "0x00000000deadbeef"),
    ];

    for (addr, expected_full, expected_modoff) in expected {
        let mut full = Vec::new();
        symb.full(addr, &mut full).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), expected_full);

        let mut modoff = Vec::new();
        symb.modoff(addr, &mut modoff).unwrap();
        assert_eq!(String::from_utf8(modoff).unwrap(), expected_modoff);
    }
}
