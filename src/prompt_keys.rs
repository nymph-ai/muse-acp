//! ACP v2 keys map to a real, once-minted MSP command ID. The retained record
//! contains hashes and IDs only. Pending records never authorize redispatch.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::editor::RequestId;
use crate::out::Echo;

pub struct Key {
    path: PathBuf,
    fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub command_id: String,
    fingerprint: String,
    pub inserted: bool,
}

pub struct Pending {
    pub key: Key,
    pub receipt: Receipt,
    pub waiters: Vec<RequestId>,
    pub content: Echo,
}

impl Key {
    pub fn new(session: &str, key: &str, texts: &[&str]) -> io::Result<Self> {
        let dir = session_dir(session)?;
        Ok(Self {
            path: dir.join(crate::sha256::hex(key.as_bytes())),
            fingerprint: crate::sha256::hex(&serde_json::to_vec(texts)?),
        })
    }

    pub fn read(&self) -> io::Result<Option<Receipt>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn matches(&self, receipt: &Receipt) -> bool {
        self.fingerprint == receipt.fingerprint
    }

    /// Atomically claim an unseen key before any native submission.
    pub fn reserve(&self, command_id: String) -> io::Result<Receipt> {
        let receipt = Receipt {
            command_id,
            fingerprint: self.fingerprint.clone(),
            inserted: false,
        };
        fs::create_dir_all(self.path.parent().expect("receipt has a directory"))?;
        self.write(&receipt, false)?;
        Ok(receipt)
    }

    pub fn confirm(&self, receipt: &mut Receipt) -> io::Result<()> {
        receipt.inserted = true;
        self.write(receipt, true)
    }

    pub fn forget(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn write(&self, receipt: &Receipt, replace: bool) -> io::Result<()> {
        let temp = self
            .path
            .with_extension(format!("{}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(receipt)?)?;
            file.sync_all()?;
            drop(file);
            if replace {
                fs::rename(&temp, &self.path)
            } else {
                fs::hard_link(&temp, &self.path)
            }
        })();
        let _ = fs::remove_file(&temp);
        result
    }
}

fn receipt_root() -> io::Result<PathBuf> {
    let root = crate::modes::state_directory().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Muse ACP has no retained state directory",
        )
    })?;
    Ok(root.join("prompt-keys"))
}

fn session_dir(session: &str) -> io::Result<PathBuf> {
    Ok(receipt_root()?.join(crate::sha256::hex(session.as_bytes())))
}

/// Advertise keyed prompts only if the retained store can reserve a key.
pub fn available() -> bool {
    let Ok(dir) = receipt_root() else {
        return false;
    };
    let probe = Key {
        path: dir.join(format!(".probe-{}", std::process::id())),
        fingerprint: String::new(),
    };
    probe.reserve(String::new()).is_ok() && probe.forget().is_ok()
}

pub fn forget_session(session: &str) {
    if let Ok(dir) = session_dir(session) {
        let _ = fs::remove_dir_all(dir);
    }
}
