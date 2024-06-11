// Axel '0vercl0k' Souchet - May 27 2024
use std::io;
use std::num::{ParseIntError, TryFromIntError};
use std::path::PathBuf;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

use pdb::PdbInternalSectionOffset;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to get rva from symbol {0} / {1:?}")]
    SymbolRva(String, PdbInternalSectionOffset),
    #[error("pdb error: {0}")]
    Pdb(#[from] pdb::Error),
    #[error("from int error: {0}")]
    FromInt(#[from] TryFromIntError),
    #[error("parse int error: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("utf8: {0}")]
    Utf8(#[from] Utf8Error),
    #[error("from utf8: {0}")]
    FromUtf8(#[from] FromUtf8Error),
    #[error("pdb path {0:?} does not have a filename")]
    PdbPathNoName(PathBuf),
    #[error("failed to perform an i/o: {0}")]
    Io(#[from] io::Error),
    #[error("failed to download pdb {pdb_url}: {e}")]
    DownloadPdb {
        pdb_url: String,
        e: Box<ureq::Error>,
    },
    #[error("the module path is either 0 or larger than reasonable")]
    CodeViewInvalidPath,
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}
