// Axel '0vercl0k' Souchet - April 21 2024
//! This module contains the [`Stats`] type that is used to keep track of
//! various statistics when symbolizing.
use std::cell::RefCell;
use std::fmt::{Debug, Display};
use std::time::Instant;

use crate::human::ToHuman;
use crate::misc::percentage;

#[derive(Debug)]
pub struct StatsBuilder {
    start: RefCell<Instant>,
    inner: RefCell<Stats>,
}

impl Default for StatsBuilder {
    fn default() -> Self {
        Self {
            start: RefCell::new(Instant::now()),
            inner: Default::default(),
        }
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    time: u64,
    n_files: u64,
    n_lines: u64,
    n_downloads: u64,
    size_downloaded: u64,
    cache_hit: u64,
}

impl StatsBuilder {
    pub fn start(&self) {
        self.start.replace_with(|_| Instant::now());
    }

    pub fn stop(&self) -> Stats {
        let elapsed = self.start.borrow().elapsed();
        let mut stats = *self.inner.borrow();
        stats.time = elapsed.as_secs();

        stats
    }

    pub fn done_file(&self, n: u64) {
        let mut inner = self.inner.borrow_mut();
        inner.n_files += 1;
        inner.n_lines += n;
    }

    pub fn downloaded_file(&self, size: u64) {
        let mut inner = self.inner.borrow_mut();
        inner.n_downloads += 1;
        inner.size_downloaded += size;
    }

    pub fn cache_hit(&self) {
        self.inner.borrow_mut().cache_hit += 1;
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "✓ Successfully symbolized {} lines across {} files in {} ({}% cache hits",
            self.n_lines.human_number(),
            self.n_files.human_number(),
            self.time.human_time(),
            percentage(self.cache_hit, self.n_lines)
        )?;

        if self.size_downloaded > 0 {
            writeln!(
                f,
                ", downloaded {} / {} PDBs)",
                self.size_downloaded.human_bytes(),
                self.n_downloads.human_number()
            )
        } else {
            writeln!(f, ")")
        }
    }
}
