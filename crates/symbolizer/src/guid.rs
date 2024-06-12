// Axel '0vercl0k' Souchet - February 20 2024
//! This module contains the implementation of the [`Guid`] type.
use std::fmt::Display;
use std::str::FromStr;

use anyhow::anyhow;

use crate::Error;

/// A GUID.
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Guid {
    d0: u32,
    d1: u16,
    d2: u16,
    d3: [u8; 8],
}

impl FromStr for Guid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(anyhow!("the guid str ({s:?}) should be 32 bytes long").into());
        }

        let mut bytes = [0; 16];
        for (n, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk)?;
            bytes[n] = u8::from_str_radix(s, 16)?;
        }

        let d0 = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let d1 = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let d2 = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let d3 = bytes[8..].try_into().unwrap();

        Ok(Self { d0, d1, d2, d3 })
    }
}

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        let d0 = u32::from_le_bytes(value[0..4].try_into().unwrap());
        let d1 = u16::from_le_bytes(value[4..6].try_into().unwrap());
        let d2 = u16::from_le_bytes(value[6..8].try_into().unwrap());
        let d3 = value[8..].try_into().unwrap();

        Self { d0, d1, d2, d3 }
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.d0,
            self.d1,
            self.d2,
            self.d3[0],
            self.d3[1],
            self.d3[2],
            self.d3[3],
            self.d3[4],
            self.d3[5],
            self.d3[6],
            self.d3[7]
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::Guid;

    const NTDLL_GUID: Guid = Guid {
        d0: 0x8d5d5ed5,
        d1: 0xd5b8,
        d2: 0xaa60,
        d3: [0x9a, 0x82, 0x60, 0x0c, 0x14, 0xe3, 0x00, 0x4d],
    };

    #[test]
    fn malformed_guids() {
        assert!(Guid::from_str("8D5D5ED5D5B8AA609A82600C14E3004D1").is_err());
        assert!(Guid::from_str("8D5D5ED5D5B8AA609A82600C14E3004").is_err());
    }

    #[test]
    fn non_hex_guids() {
        assert!(Guid::from_str("8D5D5ED5D5B8AA609A82600C14E3004Z").is_err());
    }

    #[test]
    fn str() {
        // 0:000> lmvm ntdll
        // Browse full module list
        // start             end                 module name
        // 00007ff9`aa450000 00007ff9`aa667000   ntdll      (pdb symbols)
        // c:\dbg\sym\ntdll.pdb\8D5D5ED5D5B8AA609A82600C14E3004D1\ntdll.pdb
        assert_eq!(
            "8D5D5ED5D5B8AA609A82600C14E3004D".parse::<Guid>().unwrap(),
            NTDLL_GUID
        )
    }

    #[test]
    fn from() {
        // 0:000> !dh ntdll
        // ...
        // SECTION HEADER #5
        //   .rdata name
        //    4D210 virtual size
        //   132000 virtual address
        //    4E000 size of raw data
        //   132000 file pointer to raw data
        //        0 file pointer to relocation table
        //        0 file pointer to line numbers
        //        0 number of relocations
        //        0 number of line numbers
        // 40000040 flags
        //          Initialized Data
        //          (no align specified)
        //          Read Only
        // ...
        // Debug Directories(4)
        //     Type       Size     Address  Pointer
        //     cv           22      15b880   15b880	Format: RSDS, guid, 1, ntdll.pdb
        //
        // 0:000> db ntdll+15b880
        // 00007ff9`aa5ab880  52 53 44 53 d5 5e 5d 8d-b8 d5 60 aa 9a 82 60 0c
        // RSDS.^]...`...`. 00007ff9`aa5ab890  14 e3 00 4d 01 00 00 00-6e 74 64
        // 6c 6c 2e 70 64  ...M....ntdll.pd

        assert_eq!(
            Guid::from([
                0xd5, 0x5e, 0x5d, 0x8d, 0xb8, 0xd5, 0x60, 0xaa, 0x9a, 0x82, 0x60, 0x0c, 0x14, 0xe3,
                0x00, 0x4d
            ]),
            NTDLL_GUID
        )
    }
}
