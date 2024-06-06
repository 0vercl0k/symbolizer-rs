// Axel '0vercl0k' Souchet - April 21 2024
//! This module contains the [`Stats`] type that is used to keep track of
//! various statistics when symbolizing.
use std::cell::RefCell;
use std::fmt::Debug;

#[derive(Debug, Default)]
pub struct StatsBuilder {
    inner: RefCell<Stats>,
}

/// Various statistics that the symbolizer keeps track of.
#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    /// The number of addresses symbolized.
    pub n_addrs: u64,
    /// The number of downloaded PDB files.
    pub n_downloads: u64,
    /// The total size in bytes of downloads.
    pub size_downloaded: u64,
    /// The number of time the address cache was a hit.
    pub cache_hit: u64,
}

impl StatsBuilder {
    pub fn build(&self) -> Stats {
        *self.inner.borrow()
    }

    pub fn downloaded_file(&self, size: u64) {
        let mut inner = self.inner.borrow_mut();
        inner.n_downloads += 1;
        inner.size_downloaded += size;
    }

    pub fn addr_symbolized(&self) {
        self.inner.borrow_mut().n_addrs += 1;
    }

    pub fn cache_hit(&self) {
        self.inner.borrow_mut().cache_hit += 1;
    }
}
