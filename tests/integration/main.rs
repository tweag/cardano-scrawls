//! Integration testing

mod hs2rs;
mod rs2hs;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Display;
use std::io::Result;
use std::path::Path;
use std::process::{Command, Stdio};

/// Default binary name (must be in `$PATH`)
const SCLS_UTIL_BIN: &str = "scls-util";

/// Namespaces supported by scls-util when generating arbitrary files.
#[derive(Hash)]
pub(crate) enum Namespace {
    BlocksV0,
    GovCommitteeV0,
    GovConstitutionV0,
    GovPParamsV0,
    GovProposalsV0,
    NonceV0,
    SnapshotsV0,
    UtxoV0,
}

impl Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::BlocksV0 => "blocks/v0",
                Self::GovCommitteeV0 => "gov/committee/v0",
                Self::GovConstitutionV0 => "gov/constitution/v0",
                Self::GovPParamsV0 => "gov/pparams/v0",
                Self::GovProposalsV0 => "gov/proposals/v0",
                Self::NonceV0 => "nonce/v0",
                Self::SnapshotsV0 => "snapshots/v0",
                Self::UtxoV0 => "utx0/v0",
            }
        )
    }
}

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
        self.command()
            .arg("verify")
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Checksum an SCLS file, by its global or namespace Merkle root.
    pub(crate) fn checksum(&self, path: &Path, namespace: Option<&str>) -> bool {
        let mut args: Vec<OsString> = vec!["checksum".into(), path.into()];
        if let Some(namespace) = namespace {
            args.extend(["--namespace".into(), namespace.into()]);
        }

        self.command()
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Generate a random SCLS file with a count of the given namespaces.
    pub(crate) fn generate(
        &self,
        namespaces: HashMap<Namespace, usize>,
    ) -> Result<tempfile::NamedTempFile> {
        let scls = tempfile::Builder::new().suffix(".scls").tempfile()?;

        let mut args: Vec<OsString> = vec!["debug".into(), "generate".into(), scls.path().into()];

        let mut total = 0;
        for (namespace, &count) in &namespaces {
            total += count;
            if count != 0 {
                args.extend(["--namespace".into(), format!("{namespace}:{count}").into()]);
            }
        }

        if total == 0 {
            return Err(std::io::Error::other("no namespaces specified"));
        }

        self.command().args(args).status()?;
        Ok(scls)
    }
}

impl Default for SclsUtil {
    fn default() -> Self {
        Self {
            bin: SCLS_UTIL_BIN.into(),
        }
    }
}
