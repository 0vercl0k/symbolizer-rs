// Axel '0vercl0k' Souchet - May 30 2024
use core::slice;
use std::io;
use std::mem::{self, MaybeUninit};

pub trait AddrSpace {
    fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize>;

    fn try_read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<Option<usize>>;

    fn read_exact_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let size = self.read_at(addr, buf)?;

        if size != buf.len() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("could read only {size} bytes instead of {}", buf.len()),
            ))
        } else {
            Ok(())
        }
    }

    fn try_read_exact_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<Option<()>> {
        let Some(size) = self.try_read_at(addr, buf)? else {
            return Ok(None);
        };

        if size != buf.len() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("could read only {size} bytes instead of {}", buf.len()),
            ))
        } else {
            Ok(Some(()))
        }
    }

    fn read_struct_at<S>(&mut self, addr: u64) -> io::Result<S>
    where
        S: Copy,
    {
        let mut t = MaybeUninit::uninit();
        let size_of_t = mem::size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of_t) };

        self.read_exact_at(addr, slice_over_t)?;

        Ok(unsafe { t.assume_init() })
    }

    fn try_read_struct_at<S>(&mut self, addr: u64) -> io::Result<Option<S>>
    where
        S: Copy,
    {
        let mut t: MaybeUninit<S> = MaybeUninit::uninit();
        let size_of_t = mem::size_of_val(&t);
        let slice_over_t =
            unsafe { slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of_t) };

        Ok(self
            .try_read_exact_at(addr, slice_over_t)?
            .map(|_| unsafe { t.assume_init() }))
    }
}
