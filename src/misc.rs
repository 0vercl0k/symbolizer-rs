// Axel '0vercl0k' Souchet - February 23 2024
//! This module contains the implementation of a bunch of misc utility functions
//! that didn't really fit anywhere else.
use std::env;
use std::path::PathBuf;

/// A relative address.
pub type Rva = u32;

/// Parse the `_NT_SYMBOL_PATH` environment variable to try the path of a symbol
/// cache.
pub fn sympath() -> Option<PathBuf> {
    let env = env::var("_NT_SYMBOL_PATH").ok()?;

    if !env.starts_with("srv*") {
        return None;
    }

    let sympath = env.strip_prefix("srv*").unwrap();
    let sympath = PathBuf::from(sympath.split('*').next().unwrap());

    if sympath.is_dir() {
        Some(sympath)
    } else {
        None
    }
}

/// Calculate a percentage value.
pub fn percentage(how_many: u64, how_many_total: u64) -> u32 {
    assert!(
        how_many_total > 0,
        "{how_many_total} needs to be bigger than 0"
    );

    ((how_many * 1_00) / how_many_total) as u32
}

/// Convert an `u64` into an hex string.
///
/// Highly inspired by 'Fast unsigned integer to hex string' by Johnny Lee:
///   - <https://johnnylee-sde.github.io/Fast-unsigned-integer-to-hex-string/>
pub fn fast_hex64(buffer: &mut [u8; 16], u: u64) -> &[u8] {
    let mut x = u as u128;

    // Arrange each digit into their own byte. Each byte will become the ascii
    // character representing its digit. For example, we want to arrange:
    //   - `0x00000000_00000000_DEADBEEF_BAADC0DE` into
    //   - `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E`.
    //
    // Here's a step by step using `0xDEADBEEF_BAADC0DE`:
    //   1. `x = 0x00000000_DEADBEEF_00000000_BAADC0DE`
    //   2. `x = 0xDEAD0000_BEEF0000_BAAD0000_C0DE0000`
    //   3. `x = 0x00DE00AD_00BE00EF_00BA00AD_00C000DE`
    //   4. `x = 0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E`
    //
    // Let's start the dance..
    x = (x & 0xFFFFFFFF_00000000) << 32 | x;
    x = ((x & 0xFFFF0000_00000000_FFFF0000) << 32) | ((x & 0xFFFF_00000000_0000FFFF) << 16);
    x = ((x & 0xFF0000_00FF0000_00FF0000_00FF0000) >> 16)
        | ((x & 0xFF000000_FF000000_FF000000_FF000000) >> 8);
    x = ((x & 0xF000F0_00F000F0_00F000F0_00F000F0) << 4) | (x & 0xF000F_000F000F_000F000F_000F000F);

    // This creates a mask where there'll be a 0x01 byte for each digit that is
    // alpha. For example, for `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E` we want:
    // `0x01010101_01010101_01010101_01000101`. The trick is to add 0x06 to each
    // byte; if the digit is 0x0A..0x0F, adding 0x06 will give 0x10..0x15 (notice
    // the leading '1'). Note that we need to ADD, not an OR :). At this point,
    // right shifting by 4 bits means to position that leading '1' in the lower
    // nibble which is then 'grabbed' via the masking with 0x01..
    let mask =
        ((x + 0x06060606_06060606_06060606_06060606) >> 4) & 0x01010101_01010101_01010101_01010101;

    // Turn each digit into their ASCII equivalent by setting the high nibble of
    // each byte to 0x3. `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E` becomes
    // `0x3D3E3A3D_3B3E3E3F_3B3A3A3D_3C303D3E`.
    x |= 0x30303030_30303030_30303030_30303030;

    // The last step is to adjust the ASCII byte for every digit that was in
    // 0xA..0xF. We basically add to each of those bytes `0x27` to make them lower
    // case alpha ASCII.
    // For example:
    //   - `0x01010101_01010101_01010101_01000101 * 0x27 =
    //     0x27272727_27272727_27272727_27002727`
    //   - `0x3D3E3A3D_3B3E3E3F_3B3A3A3D_3C303D3E +
    //     0x27272727_27272727_27272727_27002727` =
    //     `0x64656164_62656566_62616164_63306465`
    //
    // Why `0x27`? Well, if we have the digit 'a', we end up with `0x3a`. ASCII
    // character for 'a' is `0x61`, so `0x61 - 0x3a = 0x27`.
    x += 0x27 * mask;

    // Transform the integer into a slice of bytes.
    buffer.copy_from_slice(&x.to_be_bytes());

    // We're done!
    buffer
}

/// Convert an `u32` into an hex string.
///
/// Highly inspired by 'Fast unsigned integer to hex string' by Johnny Lee:
///   - <https://johnnylee-sde.github.io/Fast-unsigned-integer-to-hex-string/>
///
/// Adapted to not bother shuffling the bytes in little endian; we simply read
/// the final integer as big endian.
pub fn fast_hex32(buffer: &mut [u8; 8], u: u32) -> &[u8] {
    let mut x = u as u64;

    // Here's a step by step using `0xDEADBEEF`:
    //   1. `x = 0x0000DEAD_0000BEEF`
    //   2. `x = 0xDE00AD00_BE00EF00`
    //   3. `x = 0x0D0E0A0D_0B0E0E0F`
    x = (x & 0xFFFF0000) << 16 | x;
    x = ((x & 0x0000FF00_0000FF00) << 16) | ((x & 0x000000FF_000000FF) << 8);
    x = ((x & 0xF000F000_F000F000) >> 4) | ((x & 0x0F000F00_0F000F00) >> 8);

    let mask = ((x + 0x06060606_06060606) >> 4) & 0x01010101_01010101;
    x |= 0x30303030_30303030;
    x += 0x27 * mask;

    buffer.copy_from_slice(&x.to_be_bytes());

    buffer
}

#[cfg(test)]
mod tests {
    use super::{fast_hex32, fast_hex64};

    #[test]
    fn hex32() {
        let mut buffer = [0; 8];
        let out = fast_hex32(&mut buffer, 0xdeadbeef);
        assert_eq!(out, &[b'd', b'e', b'a', b'd', b'b', b'e', b'e', b'f']);
        let out = fast_hex32(&mut buffer, 0xdead);
        assert_eq!(out, &[b'0', b'0', b'0', b'0', b'd', b'e', b'a', b'd']);
        let out = fast_hex32(&mut buffer, 0x0);
        assert_eq!(out, &[b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0']);
    }

    #[test]
    fn hex64() {
        let mut buffer = [0; 16];
        let out = fast_hex64(&mut buffer, 0xdeadbeef_baadc0de);
        assert_eq!(out, &[
            b'd', b'e', b'a', b'd', b'b', b'e', b'e', b'f', b'b', b'a', b'a', b'd', b'c', b'0',
            b'd', b'e'
        ]);
        let out = fast_hex64(&mut buffer, 0xdeadbeef);
        assert_eq!(out, &[
            b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'd', b'e', b'a', b'd', b'b', b'e',
            b'e', b'f'
        ]);
        let out = fast_hex64(&mut buffer, 0x0);
        assert_eq!(out, &[
            b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
            b'0', b'0'
        ]);
    }
}
