//! ACP v2 keys map to a real, once-minted MSP command ID. The retained record
//! contains hashes and IDs only. Pending records never authorize redispatch.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::editor::RequestId;
use crate::out::Echo;
use crate::request::{Block, Content};

/// The ordinary v2 content that can use MSP's retained turn receipts.
pub struct Input<'a>(Vec<Part<'a>>);

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Part<'a> {
    Text {
        text: &'a str,
    },
    ResourceLink {
        uri: &'a str,
        name: &'a str,
        mime_type: Option<&'a str>,
    },
}

impl<'a> Input<'a> {
    pub fn from_blocks(blocks: &'a [Block]) -> Option<Self> {
        if blocks.is_empty() {
            return None;
        }
        blocks
            .iter()
            .map(|block| match &block.content {
                Content::Text(text) if !text.starts_with('/') => Some(Part::Text { text }),
                Content::ResourceLink {
                    uri,
                    name,
                    mime_type,
                } if !uri.trim().is_empty() => Some(Part::ResourceLink {
                    uri,
                    name,
                    mime_type: mime_type.as_deref(),
                }),
                _ => None,
            })
            .collect::<Option<_>>()
            .map(Self)
    }

    /// MSP has no resource-link part. Keep the reference in the native text
    /// the provider and retained user item see, without dereferencing it.
    pub fn text(&self) -> String {
        self.0
            .iter()
            .map(|part| match part {
                Part::Text { text } => (*text).to_owned(),
                Part::ResourceLink { uri, name, .. } => {
                    let label = if name.is_empty() { uri } else { name };
                    format!("[resource: {label} ({uri})]")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fingerprint(&self) -> io::Result<String> {
        let previous: Option<Vec<_>> = self
            .0
            .iter()
            .map(|part| match part {
                Part::Text { text } => Some(*text),
                Part::ResourceLink { .. } => None,
            })
            .collect();
        // Existing plain-text receipts were hashes of an array of strings.
        // A mixed prompt uses objects, so it cannot alias a string receipt.
        let bytes = match previous {
            Some(texts) => serde_json::to_vec(&texts)?,
            None => serde_json::to_vec(&self.0)?,
        };
        Ok(crate::sha256::hex(&bytes))
    }
}

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
    pub fn new(session: &str, key: &str, input: &Input<'_>) -> io::Result<Self> {
        let dir = session_dir(session)?;
        Ok(Self {
            path: dir.join(crate::sha256::hex(key.as_bytes())),
            fingerprint: input.fingerprint()?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_receipts_keep_the_existing_hash_and_link_hashes_include_the_uri() {
        let old = Input(vec![
            Part::Text { text: "hello" },
            Part::Text { text: "world" },
        ]);
        assert_eq!(
            old.fingerprint().unwrap(),
            crate::sha256::hex(br#"["hello","world"]"#)
        );
        let linked = |uri| {
            Input(vec![
                Part::Text { text: "hello" },
                Part::ResourceLink {
                    uri,
                    name: "example",
                    mime_type: None,
                },
            ])
        };
        let input = linked("https://example.invalid/first");
        assert_eq!(
            input.text(),
            "hello\n[resource: example (https://example.invalid/first)]"
        );
        assert_ne!(
            input.fingerprint().unwrap(),
            linked("https://example.invalid/second")
                .fingerprint()
                .unwrap()
        );
        assert_ne!(
            input.fingerprint().unwrap(),
            Input(vec![
                Part::Text { text: "hello" },
                Part::Text {
                    text: "[resource: example (https://example.invalid/first)]"
                },
            ])
            .fingerprint()
            .unwrap()
        );
    }
}
