// Axel '0vercl0k' Souchet - March 8 2024
//! This module contains an iterator that yields `u64` addresses converted from
//! hexadecimal strings read out of a `Reader`. I needed to implement this to
//! avoid having allocation / deallocation in the fast path when reading input
//! traces (`read_line`, `read_until`, etc. allocate a heap buffer).
use std::io::Read;
use std::ops::RangeTo;

use anyhow::{anyhow, bail, Context, Result};

/// Fill a `buffer` starting at the offset `append_idx` and return the slice of
/// data that was read. Also, return if EOF was hit or not.
fn fill_buffer<'buffer>(
    reader: &mut impl Read,
    buffer: &'buffer mut [u8],
    append_idx: usize,
) -> Result<(&'buffer [u8], bool)> {
    // Special note; we need to loop until we read what we wanted because `read`
    // doesn't guarantee to return as much data as you've asked, even if it isn't
    // EOF. To work around that, we loop and call it as much as we need.
    //   > It is not an error if the returned value n is smaller than the buffer
    //   > size,
    //   > even when the reader is not at the end of the stream yet. This may happen
    //   > for
    //   > example because fewer bytes are actually available right now (e. g. being
    //   > close to end-of-file) or because read() was interrupted by a signal.
    //   > Source: https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
    // Note that `read_exact` is also not desirable here, because we 'The contents
    // of buf are unspecified in this case.'.
    let mut append_idx = append_idx;
    let mut amount_wanted = buffer.len() - append_idx;
    let mut eof = false;
    while amount_wanted > 0 {
        // Let's read into the buffer!
        let amount_read = reader.read(&mut buffer[append_idx..])?;
        // If we didn't read anything, it means we hit EOF. Break
        // out of the loop to handle the state of the current buffer, and we'll return
        // `None`` the next time the iterator is called.
        if amount_read == 0 {
            eof = true;
            break;
        }

        // If we need to call read again, we need to do a bit of bookkeeping.
        amount_wanted -= amount_read;
        append_idx += amount_read;
    }

    // We read as much as we wanted, and we didn't hit EOF.
    let parse_slice = &buffer[..append_idx];

    // We're done.
    Ok((parse_slice, eof))
}

/// Convert an hex string into an integer.
///
/// Implementation from Johnny Lee documented in the "Fast hex number string to
/// int" blog post: <https://johnnylee-sde.github.io/Fast-hex-number-string-to-int/>.
fn fast_hex_str_to_u32(hex: [u8; 8]) -> u32 {
    let eight = unsafe { std::mem::transmute::<[u8; 8], u64>(hex) };
    let n = eight & 0x4F4F4F4F_4F4F4F4F;
    let alphahex = n & 0x40404040_40404040;
    let n0 = if alphahex == 0 {
        n
    } else {
        (alphahex >> 6).wrapping_mul(9) + (n ^ alphahex)
    };

    let n1 = n0.wrapping_mul(0x10_01) >> 8;
    let n2 = (n1 & 0x00FF00FF_00FF00FF).wrapping_mul(0x0100_0001) >> 16;

    ((n2 & 0x0000FFFF_0000FFFF).wrapping_mul(0x00010000_00000001) >> 32) as u32
}

/// Convert the `slice` of an hexadecimal string into an integer.
fn hex_slice(slice: &[u8]) -> Result<u64> {
    let slice = slice.strip_prefix(&[b'0', b'x']).unwrap_or(slice);
    if slice.len() > 16 {
        bail!("{slice:?} has more digits than supported (16)");
    }

    if !slice
        .iter()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c) || (b'A'..=b'F').contains(c))
    {
        bail!("{slice:?} has a non hex digit");
    }

    let mut buffer = [b'0'; 16];
    let idx = buffer.len() - slice.len();
    buffer[idx..].copy_from_slice(slice);
    let mut res = fast_hex_str_to_u32(buffer[0..8].try_into().unwrap()) as u64;
    res = res.wrapping_mul(0x1_00000000);
    res = res.wrapping_add(fast_hex_str_to_u32(buffer[8..16].try_into().unwrap()) as u64);

    Ok(res)
}

/// Iterator that yields `u64` integer converted from hexadecimal strings read
/// out of an object that implements [`Read`] without allocating any memory.
/// Everything is stored in a small local array. Caveats is that we expect lines
/// to be at most 20 bytes long (`len('0xdeadbeefbaadc0de\r\n')`) and it is
/// assumed to be hexadecimal.
/// For example, the below content should yield `[0x1, 0x22, 0x333, 0x4444,
/// 0x55555, 0x666666, 0x7777777, 0x88888888, 0x999999999, 0xaaaaaaaaaa]`:
///   ```
///   0x1
///   0x22
///   0x333
///   0x4444
///   0x55555
///   0x666666
///   0x7777777
///   0x88888888
///   0x999999999
///   0xaaaaaaaaaa
///   ```
#[derive(Debug)]
pub struct HexAddressesIterator<R>
where
    R: Read,
{
    /// What we read out of.
    reader: R,
    /// The local buffer where we'll read the addresses into.
    buf: [u8; 20],
    /// The index where we read / append data.
    append_idx: usize,
    /// This is the last range of data that needs consuming before the iterator
    /// returns [`None`].
    last_range: Option<RangeTo<usize>>,
    /// When set, the iterator will return [`None`] next time it is called.
    done: bool,
}

impl<R> HexAddressesIterator<R>
where
    R: Read,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: [0; 20],
            append_idx: 0,
            last_range: None,
            done: false,
        }
    }
}

impl<R> Iterator for HexAddressesIterator<R>
where
    R: Read,
{
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        // If this flag is on, it means we are done!
        if self.done {
            return None;
        }

        // If we have one last range of data to consume, then let's do that.
        if let Some(last_range) = self.last_range {
            let last_slice = &self.buf[last_range];
            // Be nice, and ignore a potential trailing end of line..
            let last_slice = last_slice.strip_suffix(&[b'\n']).unwrap_or(last_slice);
            // ..and if there's a carriage return right before, let's ignore this one as
            // well.
            let last_slice = last_slice
                .last()
                .and_then(|&last| {
                    if last == b'\r' {
                        Some(&last_slice[..(last_slice.len() - 1)])
                    } else {
                        None
                    }
                })
                .unwrap_or(last_slice);
            // This is the last range of data we'll consume, so make sure the next time the
            // iterator is called it returns `None`.
            self.done = true;
            // Yield our last address!
            return match hex_slice(last_slice) {
                Ok(o) => Some(Ok(o)),
                Err(e) => Some(Err(e)),
            };
        }

        // Let's read data into our buffer. This is what it could look like:
        // |0|x|a|a|b|b|c|c|d|d|\r|\n|0|x|e|e|f|f|d|d|
        let (parse_slice, eof) = {
            match fill_buffer(&mut self.reader, &mut self.buf, self.append_idx) {
                Ok(o) => o,
                Err(e) => return Some(Err(e)),
            }
        };

        // If we have an empty slice to parse, well we're done.
        if parse_slice.is_empty() {
            return None;
        }

        // Find a line feed and where the next 'chunk' starts at.
        // |0|x|a|a|b|b|c|c|d|d|\r|\n|0|x|e|e|f|f|d|d|
        //                         ^
        let (addr_str, next_slice_idx) = match parse_slice.iter().position(|x| *x == b'\n') {
            // If we found a line feed, then the next chunk starts right after it and we return the
            // slice up until that point. But there might be a carriage return right
            // before the line feed so take care of that.
            // |0|x|a|a|b|b|c|c|d|d|\r|\n|0|x|e|e|f|f|d|d|
            //  ^^^^^^^^^^^^^^^^^^^       ^
            //     what we return         where the next slice starts at
            Some(idx) => {
                let without_lf = &parse_slice[..idx];
                let without_cr = without_lf.strip_suffix(&[b'\r']);

                (without_cr.unwrap_or(without_lf), idx + 1)
            }
            None => {
                // If we haven't found any end line, well let's consider this the end. This
                // current entry will be the last one we yield.
                self.done = true;

                (parse_slice, 0)
            }
        };

        // Convert the byte slice into an address.
        let addr = match hex_slice(addr_str)
            .with_context(|| anyhow!("failed to turn {addr_str:?} into an integer"))
        {
            Ok(o) => o,
            Err(e) => return Some(Err(e)),
        };

        // If we hit the EOF, let's record the last range of data we'll consume.
        if eof {
            // This is the data that comes right after the current entry / after
            // the line ending characters.
            let next_slice = &parse_slice[next_slice_idx..];
            if next_slice.is_empty() {
                self.done = true;
            } else {
                self.last_range = Some(..next_slice.len());
            }
        }

        // We are done parsing. We move the rest of the buffer back to the start.
        // Before: |0|x|a|a|b|b|c|c|d|d|\r|\n|0|x|e|e|f|f|d|d|
        //  After: |0|x|e|e|f|f|d|d|d|d|\r|\n|0|x|e|e|f|f|d|d|
        self.buf.copy_within(next_slice_idx.., 0);
        // We also need to remember at what offset we'll read in new data in our buffer.
        // |0|x|e|e|f|f|d|d|d|d|\r|\n|0|x|e|e|f|f|d|d|
        //                  ^
        self.append_idx = self.buf.len() - next_slice_idx;

        // Booyah we did it!
        Some(Ok(addr))
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use anyhow::Result;

    use super::HexAddressesIterator;

    #[test]
    fn t1() {
        let expected = vec![
            0x1,
            0x22,
            0x333,
            0x4444,
            0x55555,
            0x666666,
            0x7777777,
            0x88888888,
            0x999999999,
            0xaaaaaaaaaa,
            0xbbbbbbbbbbb,
            0xcccccccccccc,
            0xddddddddddddd,
            0xeeeeeeeeeeeeee,
            0xfffffffffffffff,
            0x1111111111111111,
        ];

        let l = String::from("0x1\n0x22\n0x333\n0x4444\n0x55555\n0x666666\n0x7777777\n0x88888888\n0x999999999\n0xaaaaaaaaaa\n0xbbbbbbbbbbb\n0xcccccccccccc\n0xddddddddddddd\n0xeeeeeeeeeeeeee\n0xfffffffffffffff\n0x1111111111111111");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t2() {
        let expected = vec![
            0x1,
            0x22,
            0x333,
            0x4444,
            0x55555,
            0x666666,
            0x7777777,
            0x88888888,
            0x999999999,
            0xaaaaaaaaaa,
            0xbbbbbbbbbbb,
            0xcccccccccccc,
            0xddddddddddddd,
            0xeeeeeeeeeeeeee,
            0xfffffffffffffff,
            0x1111111111111111,
        ];
        let l = String::from("1\n22\n333\n4444\n55555\n666666\n7777777\n88888888\n999999999\naaaaaaaaaa\nbbbbbbbbbbb\ncccccccccccc\nddddddddddddd\neeeeeeeeeeeeee\nfffffffffffffff\n1111111111111111");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t3() {
        let expected = vec![0xaaaaaaaaaaaaaaau64, 0];
        let l = String::from("0xaaaaaaaaaaaaaaa\r\n0");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t4() {
        let expected = vec![
            0x77baa2c0,
            0xfffff80339dca5c0,
            0xfffff80339dca5c1,
            0xfffff80339dca5c8,
            0xfffff80339dca5d0,
            0xfffff80339dca5d4,
            0xfffff80339dca5d8,
            0xfffff80339dca5dc,
            0xfffff80339dca5e0,
            0xfffff80339dca5e4,
        ];
        let l = String::from("0x77baa2c0\n0xfffff80339dca5c0\n0xfffff80339dca5c1\n0xfffff80339dca5c8\n0xfffff80339dca5d0\n0xfffff80339dca5d4\n0xfffff80339dca5d8\n0xfffff80339dca5dc\n0xfffff80339dca5e0\n0xfffff80339dca5e4");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t5() {
        let expected = vec![
            0xfffff80339cf61a6,
            0xfffff80339cf6150,
            0xfffff80339cf6154,
            0xfffff80339cf615b,
            0xfffff80339cf6140,
            0xfffff80339cf6143,
            0xfffff80339cf6146,
            0xfffff80339cf6149,
        ];
        let l = String::from("0xfffff80339cf61a6\r\n0xfffff80339cf6150\r\n0xfffff80339cf6154\r\n0xfffff80339cf615b\r\n0xfffff80339cf6140\r\n0xfffff80339cf6143\r\n0xfffff80339cf6146\r\n0xfffff80339cf6149\r\n");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t6() {
        let expected = vec![0x1111111, 0x22222222];
        let l = String::from("0x1111111\n0x22222222");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t7() {
        let expected = vec![0xaabbccddeeff0011];
        let l = String::from("0xaabbccddeeff0011");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn t8() {
        let expected = vec![0xaaaa, 0xbbbbb];
        let l = String::from("0xaaaa\n0xbbbbb");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn allow_empty_line() {
        let expected = vec![0xaaaa, 0xbbbbb];
        let l = String::from("0xaaaa\n0xbbbbb\n");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );

        let l = String::from("0xaaaa\r\n0xbbbbb\r\n");
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }

    #[test]
    fn too_big() {
        let l = String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n0xbbbbb\n");
        assert!(HexAddressesIterator::new(BufReader::new(l.as_bytes()))
            .collect::<Result<Vec<u64>>>()
            .is_err());
    }

    #[test]
    fn malformed_entry() {
        let l = String::from("aaaaa0xa\n0xbbbbb");
        assert!(HexAddressesIterator::new(BufReader::new(l.as_bytes()))
            .collect::<Result<Vec<u64>>>()
            .is_err());
    }

    #[test]
    fn malformed_end() {
        let l = String::from("aaaaa0xa\n0xbbbbb\n\n");
        assert!(HexAddressesIterator::new(BufReader::new(l.as_bytes()))
            .collect::<Result<Vec<u64>>>()
            .is_err());
    }

    #[test]
    fn empty() {
        let l = String::from("0x77cb27c4\n0x77cb27c5\n0x77cb27c9\n");
        let expected = vec![0x77cb27c4, 0x77cb27c5, 0x77cb27c9];
        assert_eq!(
            expected,
            HexAddressesIterator::new(BufReader::new(l.as_bytes()))
                .collect::<Result<Vec<u64>>>()
                .unwrap()
        );
    }
}
