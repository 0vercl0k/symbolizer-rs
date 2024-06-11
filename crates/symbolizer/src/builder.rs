// Axel '0vercl0k' Souchet - June 7 2024
use std::path::{Path, PathBuf};

use crate::symbolizer::{Config, PdbLookupMode};
use crate::{AddrSpace, Module, Result, Symbolizer};

#[derive(Default)]
pub struct NoSymcache;

pub struct Symcache(PathBuf);

/// Builder for [`Symbolizer`].
#[derive(Default, Debug)]
pub struct Builder<SC> {
    symcache: SC,
    modules: Vec<Module>,
    mode: PdbLookupMode,
}

impl<SC> Builder<SC> {
    pub fn msft_symsrv(self) -> Builder<SC> {
        let Self {
            symcache, modules, ..
        } = self;

        Builder {
            symcache,
            modules,
            mode: PdbLookupMode::Online {
                symsrvs: vec!["https://msdl.microsoft.com/download/symbols/".into()],
            },
        }
    }

    pub fn online(self, symsrvs: impl Iterator<Item = impl Into<String>>) -> Builder<SC> {
        let Self {
            symcache, modules, ..
        } = self;

        Builder {
            symcache,
            modules,
            mode: PdbLookupMode::Online {
                symsrvs: symsrvs.map(Into::into).collect(),
            },
        }
    }
}

impl Builder<NoSymcache> {
    pub fn symcache(self, cache: &impl AsRef<Path>) -> Builder<Symcache> {
        let Self { modules, mode, .. } = self;

        Builder {
            symcache: Symcache(cache.as_ref().to_path_buf()),
            modules,
            mode,
        }
    }
}

impl<SC> Builder<SC> {
    pub fn modules<'a>(mut self, modules: impl IntoIterator<Item = &'a Module>) -> Self {
        self.modules = modules.into_iter().cloned().collect();

        self
    }
}

impl Builder<Symcache> {
    pub fn build<AS>(self, addr_space: &mut AS) -> Result<Symbolizer<AS>>
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
            mode,
        };

        Symbolizer::new(addr_space, config)
    }
}
