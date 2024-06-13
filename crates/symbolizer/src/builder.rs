// Axel '0vercl0k' Souchet - June 7 2024
use std::path::{Path, PathBuf};

use anyhow::anyhow;

use crate::symbolizer::{Config, PdbLookupMode};
use crate::{Module, Result, Symbolizer};

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
        self.online(vec!["https://msdl.microsoft.com/download/symbols/"])
    }

    pub fn online(self, symsrvs: impl IntoIterator<Item = impl Into<String>>) -> Builder<SC> {
        let Self {
            symcache, modules, ..
        } = self;

        Builder {
            symcache,
            modules,
            mode: PdbLookupMode::Online {
                symsrvs: symsrvs.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl Builder<NoSymcache> {
    pub fn symcache(self, cache: impl AsRef<Path>) -> Builder<Symcache> {
        let Self { modules, mode, .. } = self;

        Builder {
            symcache: Symcache(cache.as_ref().to_path_buf()),
            modules,
            mode,
        }
    }
}

impl<SC> Builder<SC> {
    pub fn modules(mut self, modules: impl IntoIterator<Item = Module>) -> Self {
        self.modules = modules.into_iter().collect();

        self
    }
}

impl Builder<Symcache> {
    pub fn build(self) -> Result<Symbolizer> {
        let Self {
            symcache,
            modules,
            mode,
        } = self;

        if !symcache.0.exists() {
            return Err(anyhow!("symcache {:?} does not exist", symcache.0).into());
        }

        let config = Config {
            symcache: symcache.0,
            modules,
            mode,
        };

        Symbolizer::new(config)
    }
}
