//! ACP cursor forks at boundaries the native host can copy exactly.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::PathBuf;

use crate::{json::J, modes, sha256};

pub struct Boundary<'a> {
    pub id: String,
    pub anchor_message: &'a str,
    pub index: usize,
    pub last_turn: &'a str,
}

pub fn boundaries<'a>(acp_sid: &str, msp_sid: &str, items: &'a [J]) -> Vec<Boundary<'a>> {
    // Folded history can move a terminal row across turns, and a damaged
    // range leaves its transcript position unknown. Neither proves a cut.
    if items.iter().any(|item| {
        item.non_empty_str("kind") == Some("damagedRange")
            || item.non_empty_str("terminalRowBeforeItemId").is_some()
    }) {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut turn = None;
    let mut finished_turns = HashSet::new();
    let mut seen_items = HashSet::new();
    let mut seen_user_messages = HashSet::new();
    let mut exact_prefix = true;
    for (index, item) in items.iter().enumerate() {
        let next_turn = item.non_empty_str("turnId");
        let kind = item.non_empty_str("kind");
        let item_id = item.non_empty_str("itemId");
        let completed = item.non_empty_str("status") == Some("completed");
        let user_message = (kind == Some("userMessage"))
            .then(|| item.non_empty_str("commandId").or(item_id))
            .flatten();
        if item_id.is_some_and(|id| !seen_items.insert(id))
            || user_message.is_some_and(|id| !seen_user_messages.insert(id))
        {
            return Vec::new();
        }
        if next_turn != turn
            && let Some(last_turn) = turn
        {
            finished_turns.insert(last_turn);
            if exact_prefix
                && completed
                && let Some(anchor_message) = user_message
                && let Some(next_turn) = next_turn
                && let Some(item_id) = item_id
            {
                let coordinates = [
                    acp_sid,
                    msp_sid,
                    last_turn,
                    next_turn,
                    item_id,
                    anchor_message,
                ];
                let bytes = serde_json::to_vec(&coordinates).expect("cursor coordinates serialize");
                result.push(Boundary {
                    id: sha256::hex(&bytes),
                    anchor_message,
                    index,
                    last_turn,
                });
            }
        }
        if next_turn.is_some_and(|id| finished_turns.contains(id)) {
            return Vec::new();
        }
        turn = next_turn;
        exact_prefix &= turn.is_some()
            && matches!(kind, Some("agentMessage" | "reminderChild" | "userMessage"))
            && item_id.is_some()
            && completed;
    }
    result
}

fn session_dir(session: &str) -> Option<PathBuf> {
    Some(
        modes::state_directory()?
            .join("fork-cursors")
            .join(sha256::hex(session.as_bytes())),
    )
}

/// Store only the issuance marker. The native log owns the cut coordinates,
/// and they are recomputed when a client presents the cursor.
pub fn remember(session: &str, acp_sid: &str, cursor: &str) -> io::Result<()> {
    let dir = session_dir(session)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Muse ACP has no retained state directory",
            )
        })?
        .join(sha256::hex(acp_sid.as_bytes()));
    fs::create_dir_all(&dir)?;
    let marker = dir.join(cursor);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(file) => file.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && marker.is_file() => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn was_issued(session: &str, acp_sid: &str, cursor: &str) -> bool {
    cursor.len() == 64
        && cursor.bytes().all(|b| b.is_ascii_hexdigit())
        && session_dir(session).is_some_and(|dir| {
            dir.join(sha256::hex(acp_sid.as_bytes()))
                .join(cursor)
                .is_file()
        })
}

pub fn forget_session(session: &str) {
    if let Some(dir) = session_dir(session) {
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(src: &str) -> Vec<J> {
        let J::Arr(items) = crate::json::parse_json(src).unwrap() else {
            panic!("expected a history array");
        };
        items
    }

    #[test]
    fn only_retained_unambiguous_native_turn_prefixes_get_cursors() {
        let history = items(
            r#"[
            {"itemId":"1","kind":"userMessage","turnId":"first","status":"completed"},
            {"itemId":"2","kind":"agentMessage","turnId":"first","status":"completed"},
            {"itemId":"3","kind":"userMessage","turnId":"second","status":"completed","commandId":"command"}
        ]"#,
        );
        let cursors = boundaries("editor", "native", &history);
        assert_eq!(cursors.len(), 1);
        assert_eq!(cursors[0].anchor_message, "command");
        assert_eq!(cursors[0].last_turn, "first");
        assert_eq!(
            cursors[0].id,
            boundaries("editor", "native", &history)[0].id
        );
        assert_ne!(cursors[0].id, boundaries("other", "native", &history)[0].id);
        for position in [
            r#"{"itemId":"4","kind":"userShell","status":"completed"}"#,
            r#"{"itemId":"4","kind":"agentMessage","turnId":"first","status":"inProgress"}"#,
        ] {
            let mut unsafe_prefix = history.clone();
            unsafe_prefix.insert(2, crate::json::parse_json(position).unwrap());
            assert!(boundaries("editor", "native", &unsafe_prefix).is_empty());
        }
        for position in [
            r#"{"itemId":"4","kind":"agentMessage","turnId":"first","status":"completed"}"#,
            r#"{"itemId":"4","kind":"toolCall","turnId":"second","status":"completed","terminalRowBeforeItemId":"2"}"#,
            r#"{"itemId":"3","kind":"agentMessage","turnId":"second","status":"completed"}"#,
        ] {
            let mut ambiguous = history.clone();
            ambiguous.push(crate::json::parse_json(position).unwrap());
            assert!(boundaries("editor", "native", &ambiguous).is_empty());
        }
    }
}
