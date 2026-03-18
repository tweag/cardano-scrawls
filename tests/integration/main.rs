//! Integration testing

mod hs2rs;
mod rs2hs;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Display;
use std::io::Result;
use std::path::Path;
use std::process::{Command, Stdio};

use proptest::prelude::Strategy;

/// Default binary name (must be in `$PATH`)
const SCLS_UTIL_BIN: &str = "scls-util";

/// Namespaces supported by scls-util when generating arbitrary files.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum Namespace {
    BlocksV0,
    GovCommitteeV0,
    GovConstitutionV0,
    GovPParamsV0,
    GovProposalsV0,
    NoncesV0,
    SnapshotsMarkV0,
    SnapshotsSetV0,
    SnapshotsGoV0,
    UtxoV0,
}

impl Namespace {
    /// Strategy for generating non-empty subsets of namespaces
    fn subset(max_size: usize) -> impl Strategy<Value = Vec<Self>> {
        let variants = vec![
            Namespace::BlocksV0,
            Namespace::GovCommitteeV0,
            Namespace::GovConstitutionV0,
            Namespace::GovPParamsV0,
            Namespace::GovProposalsV0,
            Namespace::NoncesV0,
            Namespace::SnapshotsMarkV0,
            Namespace::SnapshotsSetV0,
            Namespace::SnapshotsGoV0,
            Namespace::UtxoV0,
        ];

        // Clamp upper limit to number of variants
        let max = max_size.min(variants.len());

        proptest::sample::subsequence(variants, 1..=max)
    }
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
                Self::NoncesV0 => "nonces/v0",
                Self::SnapshotsMarkV0 => "snapshots/mark/v0",
                Self::SnapshotsSetV0 => "snapshots/set/v0",
                Self::SnapshotsGoV0 => "snapshots/go/v0",
                Self::UtxoV0 => "utxo/v0",
            }
        )
    }
}

/// Wrapper for scls-util functionality.
struct SclsUtil {
    bin: OsString,
}

impl SclsUtil {
    fn command(&self) -> Command {
        Command::new(&self.bin)
    }

    /// Create a new instance, if scls-util is available.
    fn probe() -> Result<Self> {
        let scls_util = SclsUtil::default();
        scls_util
            .command()
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        Ok(scls_util)
    }

    /// Check the checksum of an SCLS file, by its global or namespace Merkle root.
    fn checksum(&self, path: &Path, namespace: Option<&str>) -> bool {
        let mut args: Vec<OsString> = vec!["checksum".into(), path.into()];
        if let Some(namespace) = namespace {
            args.extend(["--namespace".into(), namespace.into()]);
        }

        self.command()
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Generate a random SCLS file with N entries per the given namespace.
    fn generate(&self, namespaces: HashMap<Namespace, usize>) -> Result<tempfile::NamedTempFile> {
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

        let status = self.command().args(args).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "{:?} exited with {status}",
                self.bin
            )));
        }

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
