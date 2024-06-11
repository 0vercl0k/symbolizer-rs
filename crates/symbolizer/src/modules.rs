// Axel '0vercl0k' Souchet - February 23 2024
//! This module contains the implementation of the [`Module`] type which is used
//! across the codebase.
use std::ops::Range;

use crate::misc::Rva;

/// A user or kernel module.
#[derive(Debug, Default, Clone)]
pub struct Module {
    /// Where the module is loaded into virtual memory.
    pub at: Range<u64>,
    /// The name of the module.
    pub name: String,
}

impl Module {
    /// Create a [`Module`].
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        Module {
            name: name.into(),
            at: start..end,
        }
    }

    /// Calculate an rva from an `addr` contained in this module.
    pub fn rva(&self, addr: u64) -> Rva {
        debug_assert!(self.at.contains(&addr));

        let offset = addr - self.at.start;
        assert!(offset <= u32::MAX.into());

        offset as Rva
    }
}

/// A list of modules.
#[derive(Debug, Default)]
pub struct Modules(Vec<Module>);

impl Modules {
    /// Create a [`Modules`].
    pub fn new(mut modules: Vec<Module>) -> Self {
        // Order the modules by their end addresses.
        modules.sort_unstable_by_key(|e| e.at.end);

        Self(modules)
    }

    /// Find the module that contains this address.
    pub fn find(&self, addr: u64) -> Option<&Module> {
        // Find the index of the first module that might contain `addr`.
        let idx = self.0.partition_point(|m| m.at.end <= addr);

        // At this point there's several cases to handle.
        //
        // `partition_point` returns the len of the vector if it couldn't
        // partition in two. This means that `addr` cannot possibly be contained by any
        // of the modules we have, so we're done.
        if idx == self.0.len() {
            return None;
        }

        // We found the first module that has an end address larger than `addr`. This
        // doesn't mean the module contains the address though. Imagine `addr` =
        // `0xdeadbeef`, and `module.at` = `[0xefefefef, 0xefefefef+1]`.
        let module = &self.0[idx];

        // For this reason, we'll make sure the `addr` is in fact included, otherwise
        // it's not a match.
        if module.at.contains(&addr) {
            Some(module)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let modules = Modules::new(vec![
            Module::new("foo".to_string(), 0x1_000, 0x2_000),
            Module::new("foobar".to_string(), 0x2_000, 0x3_000),
            Module::new("bar".to_string(), 0x4_000, 0x5_000),
        ]);

        assert!(modules.find(1).is_none());
        assert_eq!(modules.find(0x1_000).unwrap().name, "foo");
        assert_eq!(modules.find(0x2_000).unwrap().name, "foobar");
        assert!(modules.find(0x3_000).is_none());
        assert_eq!(modules.find(0x4_fff).unwrap().name, "bar");
        assert!(modules.find(0x6_000).is_none());
    }
}
