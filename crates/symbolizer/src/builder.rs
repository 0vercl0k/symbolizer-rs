// Axel '0vercl0k' Souchet - June 7 2024
use std::path::{Path, PathBuf};

use crate::symbolizer::{Config, PdbLookupMode};
use crate::{AddrSpace, Module, Result, Symbolizer};

#[derive(Default)]
pub struct NoSymcache;

pub struct Symcache(PathBuf);

#[derive(Default, Debug)]
pub struct Builder<SC, M> {
    symcache: SC,
    modules: Vec<Module>,
    mode: M,
}

#[derive(Default)]
pub struct Offline;
pub struct Online(Vec<String>);

impl<SC> Builder<SC, Offline> {
    pub fn online(self, symsrvs: impl Iterator<Item = impl Into<String>>) -> Builder<SC, Online> {
        let Self {
            symcache, modules, ..
        } = self;

        Builder {
            symcache,
            modules,
            mode: Online(symsrvs.map(Into::into).collect()),
        }
    }
}

impl<M> Builder<NoSymcache, M> {
    pub fn symcache(self, cache: &impl AsRef<Path>) -> Builder<Symcache, M> {
        let Self { modules, mode, .. } = self;

        Builder {
            symcache: Symcache(cache.as_ref().to_path_buf()),
            modules,
            mode,
        }
    }
}

impl<SC, M> Builder<SC, M> {
    pub fn modules(mut self, modules: impl Iterator<Item = Module>) -> Self {
        self.modules = modules.collect();

        self
    }
}

impl Builder<Symcache, Offline> {
    pub fn build<AS>(self, addr_space: AS) -> Result<Symbolizer<AS>>
    where
        AS: AddrSpace,
    {
        let Self {
            symcache, modules, ..
        } = self;
        let config = Config {
            symcache: symcache.0,
            modules,
            mode: PdbLookupMode::Offline,
        };

        Symbolizer::new(addr_space, config)
    }
}

impl Builder<Symcache, Online> {
    pub fn build<AS>(self, addr_space: AS) -> Result<Symbolizer<AS>>
    where
        AS: AddrSpace,
    {
        let Self {
            symcache,
            modules,
            mode,
        } = self;
        let config = Config {
            symcache: symcache.0,
            modules,
            mode: PdbLookupMode::Online { symcache: mode.0 },
        };

        Symbolizer::new(addr_space, config)
    }
}
