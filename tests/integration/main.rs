//! Integration testing

mod hs2rs;
mod rs2hs;

use std::ffi::OsString;
use std::io::Result;
use std::path::Path;
use std::process::{Command, Stdio};

/// Default binary name (must be in `$PATH`)
const SCLS_UTIL_BIN: &str = "scls-util";

/// Wrapper for scls-util functionality.
pub(crate) struct SclsUtil {
    bin: OsString,
}

impl SclsUtil {
    fn command(&self) -> Command {
        Command::new(&self.bin)
    }

    /// Create a new instance, if scls-util is available.
    pub(crate) fn probe() -> Result<Self> {
        let scls_util = SclsUtil::default();
        scls_util
            .command()
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        Ok(scls_util)
    }

    /// Verify an SCLS file.
    pub(crate) fn verify(&self, path: &Path) -> bool {
        self.command().arg("verify").arg(path).status().is_ok()
    }

    /// Checksum an SCLS file, but its global or namespace Merkle root.
    pub(crate) fn checksum(&self, path: &Path, namespace: Option<&str>) -> bool {
        let mut args: Vec<OsString> = vec!["checksum".into(), path.into()];
        if let Some(namespace) = namespace {
            args.extend(["--namespace".into(), namespace.into()]);
        }

        self.command().args(args).status().is_ok()
    }
}

impl Default for SclsUtil {
    fn default() -> Self {
        Self {
            bin: SCLS_UTIL_BIN.into(),
        }
    }
}
