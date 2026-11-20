//! Client MCP servers: ACP `mcpServers` to MSP `config.mcpServers`.
//!
//! ACP editors attach MCP servers to session setup (Zed's context servers,
//! the JetBrains IDE server). MSP 1.3.0 accepts them on `session/start` and
//! `session/resume` as a typed map keyed by server name, behind the
//! `sessionMcp` capability. Entries are translated one by one. An entry Muse
//! cannot run is dropped with a log line instead of failing the session,
//! because the host rejects the whole session for one malformed server. The
//! SDK has already refused a request whose servers do not fit the schema.
//!
//! Every server is sent as `optional`: ACP has no required servers, and a
//! required server that fails to start makes every turn fail. Log lines name
//! servers and transports only; commands, arguments, URLs, environment values
//! and headers can carry credentials and are never echoed.

use crate::json::esc;
use crate::request::McpServer;

use std::path::{Path, PathBuf};

const REPLY_NAME: &str = "fabric-channel-reply";
const REPLY_KEY: &str = "FABD_CHANNEL_REPLY_KEY";
const REPLY_HELLO: &str = "FABD_CHANNEL_REPLY_OWNER_HELLO";

fn configured_reply_paths() -> Option<(PathBuf, PathBuf)> {
    let tool = PathBuf::from(std::env::var_os("MUSE_ACP_CHANNEL_REPLY_TOOL")?);
    let socket = PathBuf::from(std::env::var_os("MUSE_ACP_CHANNEL_REPLY_SOCKET")?);
    (tool.is_absolute() && socket.is_absolute()).then_some((tool, socket))
}

pub fn reply_scope_configured() -> bool {
    configured_reply_paths().is_some()
}

/// Serialize the native unloaded-state check and the attach across all
/// fabd listeners that address this one Muse session server.
#[cfg(unix)]
pub fn lock_reply_scope() -> std::io::Result<Option<std::fs::File>> {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};

    if !reply_scope_configured() {
        return Ok(None);
    }
    let invalid = || {
        Error::new(
            ErrorKind::PermissionDenied,
            "invalid Muse reply lock location",
        )
    };
    let native_dir = if let Some(socket) = std::env::var_os("MUSE_ACP_CHANNEL_REPLY_NATIVE_SOCKET")
    {
        let socket = PathBuf::from(socket);
        if !socket.is_absolute() {
            return Err(invalid());
        }
        let socket = fs::canonicalize(socket)?;
        if !fs::metadata(&socket)?.file_type().is_socket() {
            return Err(invalid());
        }
        socket.parent().ok_or_else(invalid)?.to_path_buf()
    } else {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            })
            .filter(|data| data.is_absolute())
            .ok_or_else(invalid)?;
        let native_dir = data.join("muse/session-server");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&native_dir)?;
        fs::canonicalize(native_dir)?
    };
    let directory = native_dir.join("acp-channel-replies");
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let owner = fs::metadata(&native_dir)?.uid();
    let directory_info = fs::symlink_metadata(&directory)?;
    if !directory_info.is_dir()
        || directory_info.mode() & 0o777 != 0o700
        || directory_info.uid() != owner
    {
        return Err(invalid());
    }
    let path = directory.join("attach.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    let on_disk = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if !on_disk.is_file()
        || opened.mode() & 0o777 != 0o600
        || opened.uid() != owner
        || (opened.dev(), opened.ino()) != (on_disk.dev(), on_disk.ino())
    {
        return Err(invalid());
    }
    file.lock()?;
    Ok(Some(file))
}

#[cfg(not(unix))]
pub fn lock_reply_scope() -> std::io::Result<Option<std::fs::File>> {
    if reply_scope_configured() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "scoped Muse channel replies require local Unix sockets",
        ));
    }
    Ok(None)
}

fn delegated_reply(entry: &McpServer) -> bool {
    entry.name() == Some(REPLY_NAME)
        || matches!(entry, McpServer::Stdio {command, env, ..}
            if Path::new(command).file_name().is_some_and(|name| name == "world-mcp-channel-reply")
                || env.iter().any(|(name, _)| name == REPLY_KEY))
}

/// The native runtime owns the MCP map until it positively releases the
/// session. Refuse changes to a loaded reply map before any MSP resume.
pub fn changes_loaded_reply(previous: Option<&str>, next: Option<&str>) -> bool {
    fn map(value: Option<&str>) -> serde_json::Value {
        value
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default()
    }
    let previous = map(previous);
    let next = map(next);
    (previous.get(REPLY_NAME).is_some() || next.get(REPLY_NAME).is_some()) && previous != next
}

/// A delegated reply tool must be the configured local executable, for the
/// exact native session being resumed. Fabd independently owns the event and
/// verifies the delegated key before it ever contacts the return source.
pub fn validate_reply_scope(
    servers: &[McpServer],
    target: Option<&str>,
) -> Result<(), &'static str> {
    let mut entries = servers.iter().filter(|entry| delegated_reply(entry));
    let Some(entry) = entries.next() else {
        return Ok(());
    };
    const INVALID: &str = "invalid scoped channel reply MCP configuration for this Muse session";
    let Some(target) = target else {
        return Err("Muse channel reply MCP requires an existing native session on ACP v2 resume");
    };
    let (expected_tool, expected_socket) =
        configured_reply_paths().ok_or("Muse channel reply MCP is not enabled for this adapter")?;
    let McpServer::Stdio {
        name,
        command,
        args,
        env,
    } = entry
    else {
        return Err(INVALID);
    };
    let [socket, session, source, event] = args.as_slice() else {
        return Err(INVALID);
    };
    let key = env.iter().any(|(name, value)| {
        name == REPLY_KEY && value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let owner_hello = env
        .iter()
        .any(|(name, value)| name == REPLY_HELLO && value == "1");
    if entries.next().is_some()
        || name != REPLY_NAME
        || Path::new(command) != expected_tool
        || Path::new(socket) != expected_socket
        || session != target
        || source.is_empty()
        || event.is_empty()
        || env.len() != 2
        || !key
        || !owner_hello
    {
        return Err(INVALID);
    }
    Ok(())
}

/// The MSP side of one ACP `mcpServers` list.
#[derive(Debug, Default)]
pub struct Translation {
    /// JSON text of the MSP `mcpServers` object, or None when nothing is
    /// forwarded.
    pub servers: Option<String>,
    /// Names of the translated servers, in client order.
    pub forwarded: Vec<String>,
    /// One diagnostic per dropped entry.
    pub dropped: Vec<String>,
}

impl Translation {
    /// Whether the client supplied any server at all, forwarded or not.
    pub fn supplied(&self) -> bool {
        !self.forwarded.is_empty() || !self.dropped.is_empty()
    }

    /// `"a", "b"` for log lines.
    pub fn names(&self) -> String {
        self.forwarded
            .iter()
            .map(|name| esc(name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Translate the client's `mcpServers`, which the SDK has already parsed
/// into their schema types. The first entry with a given name wins, since MSP
/// keys servers by name.
pub fn translate(servers: &[McpServer]) -> Translation {
    let mut translation = Translation::default();
    let mut members = Vec::new();
    for (index, entry) in servers.iter().enumerate() {
        match server(entry) {
            Ok((name, _)) if translation.forwarded.contains(&name) => {
                translation
                    .dropped
                    .push(format!("MCP server {} dropped: duplicate name", esc(&name)));
            }
            Ok((name, value)) => {
                members.push(format!("{}:{value}", esc(&name)));
                translation.forwarded.push(name);
            }
            Err(reason) => translation.dropped.push(format!(
                "MCP server {} dropped: {reason}",
                label(entry, index)
            )),
        }
    }
    if !members.is_empty() {
        translation.servers = Some(format!("{{{}}}", members.join(",")));
    }
    translation
}

fn label(entry: &McpServer, index: usize) -> String {
    match entry.name() {
        Some(name) if !name.is_empty() => esc(name),
        _ => format!("#{index}"),
    }
}

/// One ACP server entry as `(name, MSP SessionMcpServerConfig JSON)`.
fn server(entry: &McpServer) -> Result<(String, String), String> {
    let name = match entry.name() {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => return Err("missing name".to_string()),
    };
    let value = match entry {
        McpServer::Stdio {
            command, args, env, ..
        } => stdio(command, args, env)?,
        McpServer::Http { url, headers, .. } => http(url, headers)?,
        McpServer::Sse { .. } => {
            return Err("the SSE transport is not supported by Muse".to_string());
        }
        McpServer::Other { kind, .. } => {
            return Err(format!("unsupported transport {}", esc(kind)));
        }
    };
    Ok((name, value))
}

fn stdio(command: &str, args: &[String], env: &[(String, String)]) -> Result<String, String> {
    if command.is_empty() {
        return Err("missing command".to_string());
    }
    let mut out = format!("{{\"transport\":\"stdio\",\"command\":{}", esc(command));
    if !args.is_empty() {
        let args: Vec<String> = args.iter().map(|arg| esc(arg)).collect();
        out.push_str(&format!(",\"args\":[{}]", args.join(",")));
    }
    if let Some(env) = pairs(env, "env")? {
        out.push_str(&format!(",\"env\":{env}"));
    }
    out.push_str(",\"mode\":\"optional\"}");
    Ok(out)
}

fn http(url: &str, headers: &[(String, String)]) -> Result<String, String> {
    if url.is_empty() {
        return Err("missing url".to_string());
    }
    let mut out = format!("{{\"transport\":\"streamableHttp\",\"url\":{}", esc(url));
    if let Some(headers) = pairs(headers, "headers")? {
        out.push_str(&format!(",\"headers\":{headers}"));
    }
    out.push_str(",\"mode\":\"optional\"}");
    Ok(out)
}

/// ACP `[{name, value}]` as an MSP string map, or None when empty. A later
/// entry replaces an earlier one with the same name, as in a process
/// environment.
fn pairs(items: &[(String, String)], key: &str) -> Result<Option<String>, String> {
    let mut map: Vec<(&str, &str)> = Vec::new();
    for (name, value) in items {
        if name.is_empty() {
            return Err(format!("{key} entries must have a name"));
        }
        match map
            .iter_mut()
            .find(|(existing, _)| *existing == name.as_str())
        {
            Some(slot) => slot.1 = value,
            None => map.push((name, value)),
        }
    }
    if map.is_empty() {
        return Ok(None);
    }
    let members = map
        .iter()
        .map(|(name, value)| format!("{}:{}", esc(name), esc(value)))
        .collect::<Vec<_>>();
    Ok(Some(format!("{{{}}}", members.join(","))))
}

#[cfg(test)]
mod tests {
    use super::translate;
    use agent_client_protocol::{v1, v2};

    /// The servers of an ACP v1 list, as the SDK parses them.
    fn run(servers: &str) -> super::Translation {
        let servers: Vec<v1::schema::McpServer> =
            serde_json::from_str(servers).expect("v1 servers");
        let servers: Vec<_> = servers.into_iter().map(crate::request::v1_mcp).collect();
        translate(&servers)
    }

    /// The servers of an ACP v2 list, as the SDK parses them.
    fn run_v2(servers: &str) -> super::Translation {
        let servers: Vec<v2::schema::McpServer> =
            serde_json::from_str(servers).expect("v2 servers");
        let servers: Vec<_> = servers.into_iter().map(crate::request::v2_mcp).collect();
        translate(&servers)
    }

    #[test]
    fn v1_untagged_stdio_becomes_an_optional_stdio_server() {
        let t = run(
            r#"[{"name":"intellij","command":"/opt/idea/bin/java","args":["-cp","x","Main"],"env":[{"name":"IJ_PORT","value":"64342"}]}]"#,
        );
        assert_eq!(
            t.servers.as_deref(),
            Some(
                r#"{"intellij":{"transport":"stdio","command":"/opt/idea/bin/java","args":["-cp","x","Main"],"env":{"IJ_PORT":"64342"},"mode":"optional"}}"#
            )
        );
        assert_eq!(t.forwarded, ["intellij"]);
        assert!(t.dropped.is_empty());
    }

    #[test]
    fn v2_tagged_stdio_and_http_are_both_forwarded() {
        let t = run_v2(
            r#"[{"type":"stdio","name":"files","command":"/bin/mcp"},{"type":"http","name":"docs","url":"https://mcp.example/mcp","headers":[{"name":"Authorization","value":"Bearer t"}]}]"#,
        );
        assert_eq!(
            t.servers.as_deref(),
            Some(
                r#"{"files":{"transport":"stdio","command":"/bin/mcp","mode":"optional"},"docs":{"transport":"streamableHttp","url":"https://mcp.example/mcp","headers":{"Authorization":"Bearer t"},"mode":"optional"}}"#
            )
        );
        assert_eq!(t.names(), r#""files", "docs""#);
    }

    #[test]
    fn an_empty_list_translates_to_nothing() {
        let t = run("[]");
        assert!(t.servers.is_none() && !t.supplied());
    }

    #[test]
    fn unsupported_entries_are_dropped_without_failing_the_rest() {
        let t = run(r#"[
                {"type":"sse","name":"legacy","url":"https://sse.example/sse","headers":[]},
                {"name":"","command":"/bin/x","args":[],"env":[]},
                {"name":"nocmd","command":"","args":[],"env":[]},
                {"type":"http","name":"nourl","url":"","headers":[]},
                {"name":"badpair","command":"/bin/x","args":[],"env":[{"name":"","value":"v"}]},
                {"name":"ok","command":"/bin/ok","args":[],"env":[]}
            ]"#);
        assert_eq!(t.forwarded, ["ok"]);
        assert_eq!(
            t.servers.as_deref(),
            Some(r#"{"ok":{"transport":"stdio","command":"/bin/ok","mode":"optional"}}"#)
        );
        assert_eq!(t.dropped.len(), 5, "{:?}", t.dropped);
        assert!(t.dropped[0].contains("\"legacy\"") && t.dropped[0].contains("SSE"));
        assert!(t.dropped[1].contains("#1") && t.dropped[1].contains("missing name"));
        assert!(t.dropped[2].contains("missing command"));
        assert!(t.dropped[3].contains("missing url"));
        assert!(t.dropped[4].contains("env entries must have a name"));
        let t = run_v2(r#"[{"type":"websocket","name":"future","url":"wss://x"}]"#);
        assert!(t.dropped[0].contains("unsupported transport \"websocket\""));
    }

    #[test]
    fn the_first_server_with_a_name_wins() {
        let t = run(
            r#"[{"name":"dup","command":"/bin/first","args":[],"env":[]},{"type":"http","name":"dup","url":"https://second","headers":[]}]"#,
        );
        assert_eq!(t.forwarded, ["dup"]);
        assert!(t.servers.as_deref().unwrap().contains("/bin/first"));
        assert!(!t.servers.as_deref().unwrap().contains("second"));
        assert_eq!(t.dropped, ["MCP server \"dup\" dropped: duplicate name"]);
    }

    #[test]
    fn a_later_environment_entry_replaces_an_earlier_one() {
        let t = run(
            r#"[{"name":"e","command":"/bin/e","args":[],"env":[{"name":"A","value":"1"},{"name":"B","value":""},{"name":"A","value":"2"}]}]"#,
        );
        assert!(
            t.servers
                .as_deref()
                .unwrap()
                .contains(r#""env":{"A":"2","B":""}"#),
            "{:?}",
            t.servers
        );
    }

    #[test]
    fn diagnostics_never_echo_commands_urls_or_secret_values() {
        let t = run(r#"[
                {"type":"sse","name":"b","url":"https://SECRET-URL","headers":[]},
                {"type":"http","name":"c","url":"https://SECRET-URL","headers":[{"name":"","value":"SECRET"}]},
                {"name":"d","command":"/secret/cmd","args":["--token","SECRET-ARG"],"env":[{"name":"TOKEN","value":"SECRET-ENV"},{"name":"","value":"x"}]},
                {"name":"e","command":"/secret/cmd","args":[],"env":[{"name":"TOKEN","value":"SECRET-ENV"}]},
                {"name":"e","command":"/secret/cmd","args":[],"env":[]}
            ]"#);
        assert_eq!(t.dropped.len(), 4, "{:?}", t.dropped);
        for line in &t.dropped {
            for secret in ["SECRET", "/secret/cmd", "Authorization", "TOKEN"] {
                assert!(!line.contains(secret), "{line}");
            }
        }
        assert!(!t.names().contains("SECRET"));
    }
}
