//! ACP v2 keys map to a real, once-minted MSP command ID. The retained record
//! stores hashes and IDs. Baseline resources add a layout and bounded MIME
//! tokens, while their prompt text and URI remain in the native transcript.
//! Pending records never authorize redispatch.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use agent_client_protocol::v2::schema::ContentBlock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::editor::RequestId;
use crate::json::J;
use crate::out::{Echo, EchoBlock};
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

impl Part<'_> {
    fn baseline(&self) -> Value {
        match self {
            Self::Text { text } => json!({"type": "text", "text": text}),
            Self::ResourceLink {
                uri,
                name,
                mime_type,
            } => {
                let mut block = json!({"type": "resource_link", "uri": uri, "name": name});
                if let Some(mime) = mime_type {
                    block["mimeType"] = json!(mime);
                }
                block
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Projection {
    text_sha256: String,
    parts: Vec<Layout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native: Option<NativeItem>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Layout {
    Text {
        bytes: usize,
    },
    ResourceLink {
        name_bytes: usize,
        uri_bytes: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NativeItem {
    item_id: String,
    turn_id: String,
}

fn mime_token(value: &str) -> bool {
    value.len() <= 127
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            [kind, subtype].iter().all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&byte))
            })
        })
}

fn take_bytes<'a>(text: &mut &'a str, bytes: usize) -> Option<&'a str> {
    let (part, rest) = text.split_at_checked(bytes)?;
    *text = rest;
    Some(part)
}

impl Projection {
    fn new(input: &Input<'_>, blocks: &[Block]) -> Option<Self> {
        if !input
            .0
            .iter()
            .any(|part| matches!(part, Part::ResourceLink { .. }))
        {
            return None;
        }
        let parts = input
            .0
            .iter()
            .zip(blocks)
            .map(|(part, block)| {
                let EchoBlock::V2(echo) = &block.echo else {
                    return None;
                };
                if serde_json::to_value(echo).ok()? != part.baseline() {
                    return None;
                }
                Some(match part {
                    Part::Text { text } => Layout::Text { bytes: text.len() },
                    Part::ResourceLink {
                        uri,
                        name,
                        mime_type,
                    } => {
                        if mime_type.is_some_and(|mime| !mime_token(mime)) {
                            return None;
                        }
                        Layout::ResourceLink {
                            name_bytes: name.len(),
                            uri_bytes: uri.len(),
                            mime_type: mime_type.map(str::to_owned),
                        }
                    }
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            text_sha256: crate::sha256::hex(input.text().as_bytes()),
            parts,
            native: None,
        })
    }

    fn witness(&self, command: &str, item: &J) -> Option<NativeItem> {
        if item.non_empty_str("kind") != Some("userMessage")
            || item.non_empty_str("commandId") != Some(command)
            || item.non_empty_str("status") != Some("completed")
            || item.get("attachments").is_some_and(|value| {
                !matches!(value, J::Null) && !matches!(value, J::Arr(items) if items.is_empty())
            })
            || item
                .get("truncated")
                .is_some_and(|value| !matches!(value, J::Null | J::Bool(false)))
            || item
                .get("cutOff")
                .is_some_and(|value| !matches!(value, J::Null | J::Bool(false)))
        {
            return None;
        }
        let text = item.non_empty_str("text")?;
        if crate::sha256::hex(text.as_bytes()) != self.text_sha256
            || item
                .get("displayText")
                .and_then(J::as_str)
                .is_some_and(|display| display != text)
        {
            return None;
        }
        let identity = NativeItem {
            item_id: item.non_empty_str("itemId")?.to_owned(),
            turn_id: item.non_empty_str("turnId")?.to_owned(),
        };
        self.native
            .as_ref()
            .is_none_or(|prior| *prior == identity)
            .then_some(identity)
    }

    fn restore(&self, receipt: &Receipt, item: &J) -> Option<Vec<ContentBlock>> {
        if !receipt.inserted || self.native.is_none() {
            return None;
        }
        self.witness(&receipt.command_id, item)?;
        let mut text = item.non_empty_str("text")?;
        let mut decoded = Vec::new();
        for (index, layout) in self.parts.iter().enumerate() {
            if index != 0 {
                text = text.strip_prefix('\n')?;
            }
            decoded.push(match layout {
                Layout::Text { bytes } => Part::Text {
                    text: take_bytes(&mut text, *bytes)?,
                },
                Layout::ResourceLink {
                    name_bytes,
                    uri_bytes,
                    mime_type,
                } => {
                    text = text.strip_prefix("[resource: ")?;
                    let label = take_bytes(
                        &mut text,
                        if *name_bytes == 0 {
                            *uri_bytes
                        } else {
                            *name_bytes
                        },
                    )?;
                    text = text.strip_prefix(" (")?;
                    let uri = take_bytes(&mut text, *uri_bytes)?;
                    text = text.strip_prefix(")]")?;
                    if *name_bytes == 0 && label != uri {
                        return None;
                    }
                    Part::ResourceLink {
                        name: if *name_bytes == 0 { "" } else { label },
                        uri,
                        mime_type: mime_type.as_deref(),
                    }
                }
            });
        }
        let restored = Input(decoded);
        if !text.is_empty() || restored.fingerprint().ok()? != receipt.fingerprint {
            return None;
        }
        restored
            .0
            .iter()
            .map(|part| serde_json::from_value(part.baseline()).ok())
            .collect()
    }
}

pub struct Key {
    path: PathBuf,
    fingerprint: String,
    projection: Option<Projection>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub command_id: String,
    fingerprint: String,
    pub inserted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    projection: Option<Projection>,
}

impl Receipt {
    pub fn accepts_recovery(&self, item: &J) -> bool {
        self.projection
            .as_ref()
            .is_none_or(|projection| projection.witness(&self.command_id, item).is_some())
    }
}

pub struct Pending {
    pub key: Key,
    pub receipt: Receipt,
    pub waiters: Vec<RequestId>,
    pub content: Echo,
}

impl Key {
    pub fn new(session: &str, key: &str, input: &Input<'_>, blocks: &[Block]) -> io::Result<Self> {
        let dir = session_dir(session)?;
        Ok(Self {
            path: dir.join(crate::sha256::hex(key.as_bytes())),
            fingerprint: input.fingerprint()?,
            projection: Projection::new(input, blocks),
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
            projection: self.projection.clone(),
        };
        fs::create_dir_all(self.path.parent().expect("receipt has a directory"))?;
        self.write(&receipt, false)?;
        Ok(receipt)
    }

    pub fn confirm(&self, receipt: &mut Receipt, item: &J) -> io::Result<()> {
        receipt.inserted = true;
        if let Some(projection) = &mut receipt.projection
            && let Some(identity) = projection.witness(&receipt.command_id, item)
        {
            projection.native = Some(identity);
        }
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
        projection: None,
    };
    probe.reserve(String::new()).is_ok() && probe.forget().is_ok()
}

/// Restore only unique native messages and unique receipts for this exact
/// session. The caller supplies the complete native inline batch, including
/// any prefix omitted from the requested replay.
pub fn replay_resources(session: &str, items: &[J]) -> HashMap<String, Vec<ContentBlock>> {
    let Ok(entries) = session_dir(session).and_then(fs::read_dir) else {
        return HashMap::new();
    };
    let mut receipts = HashMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(|name| {
            name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) || !entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            continue;
        }
        let Some(receipt) = fs::read(entry.path())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Receipt>(&bytes).ok())
        else {
            continue;
        };
        receipts
            .entry(receipt.command_id.clone())
            .and_modify(|prior| *prior = None)
            .or_insert(Some(receipt));
    }

    let mut command_counts = HashMap::new();
    let mut item_counts = HashMap::new();
    for item in items {
        if let Some(id) = item.non_empty_str("itemId") {
            *item_counts.entry(id).or_insert(0) += 1;
        }
        if let Some(command) = item.non_empty_str("commandId") {
            *command_counts.entry(command).or_insert(0) += 1;
        }
    }

    items
        .iter()
        .filter_map(|item| {
            let command = item.non_empty_str("commandId")?;
            let item_id = item.non_empty_str("itemId")?;
            if command_counts.get(command) != Some(&1) || item_counts.get(item_id) != Some(&1) {
                return None;
            }
            let receipt = receipts.get(command)?.as_ref()?;
            let projection = receipt.projection.as_ref()?;
            Some((command.to_owned(), projection.restore(receipt, item)?))
        })
        .collect()
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
