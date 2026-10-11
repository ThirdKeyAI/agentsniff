//! Zeek log data source — supports both JSON-lines and TSV output formats.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::{DataSource, DnsRecord, TlsRecord, TrafficRecord};

const MAX_ZEEK_LOG_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZEEK_LINE_BYTES: usize = 1024 * 1024;
const MAX_ZEEK_RECORDS: usize = 100_000;

/// The two output formats supported by Zeek.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeekFormat {
    Json,
    Tsv,
}

/// Detect whether a line is JSON or TSV.
///
/// A line that starts with `{` (after trimming) is treated as JSON;
/// everything else is treated as TSV (including Zeek metadata comments).
pub fn detect_format(line: &str) -> ZeekFormat {
    if line.trim_start().starts_with('{') {
        ZeekFormat::Json
    } else {
        ZeekFormat::Tsv
    }
}

/// Parse a `#fields` header line into a list of column names.
///
/// Input example: `#fields\tts\tuid\tid.orig_h\t...`
pub fn parse_fields_header(line: &str) -> Vec<String> {
    let parts: Vec<&str> = line.split('\t').collect();
    // parts[0] is "#fields"; the rest are the column names
    parts
        .into_iter()
        .skip(1)
        .map(|s| s.trim().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Internal TSV helpers
// ---------------------------------------------------------------------------

/// Look up a field by name in a tab-split line, returning `None` when the
/// value is `-` (Zeek's "unset" sentinel) or the column is absent.
fn tsv_field<'a>(parts: &[&'a str], fields: &[String], name: &str) -> Option<&'a str> {
    let idx = fields.iter().position(|f| f == name)?;
    let val = parts.get(idx).copied()?;
    if val == "-" {
        None
    } else {
        Some(val)
    }
}

/// Like [`tsv_field`] but returns `default` when the column is absent or `-`.
fn tsv_field_or<'a>(parts: &[&'a str], fields: &[String], name: &str, default: &'a str) -> &'a str {
    tsv_field(parts, fields, name).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Trait for generic filtering
// ---------------------------------------------------------------------------

pub trait HasTimestampAndIps {
    fn timestamp(&self) -> f64;
    fn involves_target(&self, targets: &HashSet<IpAddr>) -> bool;
}

impl HasTimestampAndIps for TrafficRecord {
    fn timestamp(&self) -> f64 {
        self.timestamp
    }
    fn involves_target(&self, targets: &HashSet<IpAddr>) -> bool {
        targets.contains(&self.src_ip) || targets.contains(&self.dst_ip)
    }
}

impl HasTimestampAndIps for DnsRecord {
    fn timestamp(&self) -> f64 {
        self.timestamp
    }
    fn involves_target(&self, targets: &HashSet<IpAddr>) -> bool {
        targets.contains(&self.src_ip)
    }
}

impl HasTimestampAndIps for TlsRecord {
    fn timestamp(&self) -> f64 {
        self.timestamp
    }
    fn involves_target(&self, targets: &HashSet<IpAddr>) -> bool {
        targets.contains(&self.src_ip) || targets.contains(&self.dst_ip)
    }
}

// ---------------------------------------------------------------------------
// conn.log  →  TrafficRecord
// ---------------------------------------------------------------------------

/// Parse a single line from a Zeek `conn.log` file.
///
/// Returns `None` for comment/empty lines or lines that cannot be parsed.
pub fn parse_conn_line(line: &str, fields: &[String], format: ZeekFormat) -> Option<TrafficRecord> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    match format {
        ZeekFormat::Json => parse_conn_json(line),
        ZeekFormat::Tsv => parse_conn_tsv(line, fields),
    }
}

fn parse_conn_json(line: &str) -> Option<TrafficRecord> {
    let v: Value = serde_json::from_str(line).ok()?;
    let timestamp = v["ts"].as_f64()?;
    let src_ip: IpAddr = v["id.orig_h"].as_str()?.parse().ok()?;
    let dst_ip: IpAddr = v["id.resp_h"].as_str()?.parse().ok()?;
    let src_port = v["id.orig_p"].as_u64()? as u16;
    let dst_port = v["id.resp_p"].as_u64()? as u16;
    let protocol = v["proto"].as_str().unwrap_or("").to_string();
    let duration = v["duration"].as_f64();
    let bytes_sent = v["orig_bytes"].as_u64().unwrap_or(0);
    let bytes_recv = v["resp_bytes"].as_u64().unwrap_or(0);
    Some(TrafficRecord {
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        duration,
        bytes_sent,
        bytes_recv,
    })
}

fn parse_conn_tsv(line: &str, fields: &[String]) -> Option<TrafficRecord> {
    let parts: Vec<&str> = line.split('\t').collect();
    let timestamp: f64 = tsv_field(&parts, fields, "ts")?.parse().ok()?;
    let src_ip: IpAddr = tsv_field(&parts, fields, "id.orig_h")?.parse().ok()?;
    let dst_ip: IpAddr = tsv_field(&parts, fields, "id.resp_h")?.parse().ok()?;
    let src_port: u16 = tsv_field(&parts, fields, "id.orig_p")?.parse().ok()?;
    let dst_port: u16 = tsv_field(&parts, fields, "id.resp_p")?.parse().ok()?;
    let protocol = tsv_field_or(&parts, fields, "proto", "").to_string();
    let duration = tsv_field(&parts, fields, "duration").and_then(|s| s.parse::<f64>().ok());
    let bytes_sent = tsv_field(&parts, fields, "orig_bytes")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let bytes_recv = tsv_field(&parts, fields, "resp_bytes")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some(TrafficRecord {
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        duration,
        bytes_sent,
        bytes_recv,
    })
}

// ---------------------------------------------------------------------------
// dns.log  →  DnsRecord
// ---------------------------------------------------------------------------

/// Parse a single line from a Zeek `dns.log` file.
pub fn parse_dns_line(line: &str, fields: &[String], format: ZeekFormat) -> Option<DnsRecord> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    match format {
        ZeekFormat::Json => parse_dns_json(line),
        ZeekFormat::Tsv => parse_dns_tsv(line, fields),
    }
}

fn parse_dns_json(line: &str) -> Option<DnsRecord> {
    let v: Value = serde_json::from_str(line).ok()?;
    let timestamp = v["ts"].as_f64()?;
    let src_ip: IpAddr = v["id.orig_h"].as_str()?.parse().ok()?;
    let query = v["query"].as_str().unwrap_or("").to_string();
    let qtype = v["qtype_name"].as_str().unwrap_or("").to_string();
    let response_ips = v["answers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str()?.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();
    Some(DnsRecord {
        timestamp,
        src_ip,
        query,
        qtype,
        response_ips,
    })
}

fn parse_dns_tsv(line: &str, fields: &[String]) -> Option<DnsRecord> {
    let parts: Vec<&str> = line.split('\t').collect();
    let timestamp: f64 = tsv_field(&parts, fields, "ts")?.parse().ok()?;
    let src_ip: IpAddr = tsv_field(&parts, fields, "id.orig_h")?.parse().ok()?;
    let query = tsv_field_or(&parts, fields, "query", "").to_string();
    let qtype = tsv_field_or(&parts, fields, "qtype_name", "").to_string();
    // answers may be a set (comma-separated in Zeek TSV)
    let response_ips = tsv_field(&parts, fields, "answers")
        .map(|s| {
            s.split(',')
                .filter_map(|a| a.trim().parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();
    Some(DnsRecord {
        timestamp,
        src_ip,
        query,
        qtype,
        response_ips,
    })
}

// ---------------------------------------------------------------------------
// ssl.log  →  TlsRecord
// ---------------------------------------------------------------------------

/// Parse a single line from a Zeek `ssl.log` file.
pub fn parse_ssl_line(line: &str, fields: &[String], format: ZeekFormat) -> Option<TlsRecord> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    match format {
        ZeekFormat::Json => parse_ssl_json(line),
        ZeekFormat::Tsv => parse_ssl_tsv(line, fields),
    }
}

fn parse_ssl_json(line: &str) -> Option<TlsRecord> {
    let v: Value = serde_json::from_str(line).ok()?;
    let timestamp = v["ts"].as_f64()?;
    let src_ip: IpAddr = v["id.orig_h"].as_str()?.parse().ok()?;
    let dst_ip: IpAddr = v["id.resp_h"].as_str()?.parse().ok()?;
    let server_name = v["server_name"].as_str().map(|s| s.to_string());
    let ja3_hash = v["ja3"].as_str().map(|s| s.to_string());
    let subject = v["subject"].as_str().map(|s| s.to_string());
    let issuer = v["issuer"].as_str().map(|s| s.to_string());
    Some(TlsRecord {
        timestamp,
        src_ip,
        dst_ip,
        server_name,
        ja3_hash,
        subject,
        issuer,
    })
}

fn parse_ssl_tsv(line: &str, fields: &[String]) -> Option<TlsRecord> {
    let parts: Vec<&str> = line.split('\t').collect();
    let timestamp: f64 = tsv_field(&parts, fields, "ts")?.parse().ok()?;
    let src_ip: IpAddr = tsv_field(&parts, fields, "id.orig_h")?.parse().ok()?;
    let dst_ip: IpAddr = tsv_field(&parts, fields, "id.resp_h")?.parse().ok()?;
    let server_name = tsv_field(&parts, fields, "server_name").map(|s| s.to_string());
    let ja3_hash = tsv_field(&parts, fields, "ja3").map(|s| s.to_string());
    let subject = tsv_field(&parts, fields, "subject").map(|s| s.to_string());
    let issuer = tsv_field(&parts, fields, "issuer").map(|s| s.to_string());
    Some(TlsRecord {
        timestamp,
        src_ip,
        dst_ip,
        server_name,
        ja3_hash,
        subject,
        issuer,
    })
}

// ---------------------------------------------------------------------------
// Generic file reader
// ---------------------------------------------------------------------------

/// Read a Zeek log file from `path`, auto-detect format, parse each line
/// with `parse_fn`, and return only records that fall within `time_window`
/// (relative to now) and involve at least one of `targets`.
///
/// An empty `targets` set means "include all records".
async fn read_log_file<T, F>(
    path: &Path,
    targets: &HashSet<IpAddr>,
    time_window: Duration,
    parse_fn: F,
) -> anyhow::Result<Vec<T>>
where
    T: HasTimestampAndIps + Send + 'static,
    F: Fn(&str, &[String], ZeekFormat) -> Option<T> + Send + Sync + 'static,
{
    read_log_file_with_limits(
        path,
        targets,
        time_window,
        parse_fn,
        MAX_ZEEK_LOG_BYTES,
        MAX_ZEEK_LINE_BYTES,
        MAX_ZEEK_RECORDS,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn read_log_file_with_limits<T, F>(
    path: &Path,
    targets: &HashSet<IpAddr>,
    time_window: Duration,
    parse_fn: F,
    max_file_bytes: u64,
    max_line_bytes: usize,
    max_records: usize,
) -> anyhow::Result<Vec<T>>
where
    T: HasTimestampAndIps + Send + 'static,
    F: Fn(&str, &[String], ZeekFormat) -> Option<T> + Send + Sync + 'static,
{
    if !path.exists() {
        return Ok(vec![]);
    }

    let path_buf = path.to_path_buf();
    let targets_clone = targets.clone();

    let records = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<T>> {
        // Open once and keep the same file description for discovery and
        // parsing so a path replacement cannot swap in a different log.
        let file = File::open(&path_buf)?;
        let metadata = file.metadata()?;
        if metadata.len() > max_file_bytes {
            anyhow::bail!(
                "Zeek log {} exceeds the {} byte limit",
                path_buf.display(),
                max_file_bytes
            );
        }

        // Make a bounded discovery pass so a valid TSV #fields line that
        // appears after early records retains the previous parser behavior.
        let mut reader = BufReader::new(file);
        let mut line_bytes = Vec::new();
        let mut format = None;
        let mut fields = Vec::new();
        let mut discovery_bytes = 0_u64;
        loop {
            let bytes_read = read_bounded_line(&mut reader, &mut line_bytes, max_line_bytes)?;
            if bytes_read == 0 {
                break;
            }
            discovery_bytes =
                checked_zeek_bytes(discovery_bytes, bytes_read, max_file_bytes, &path_buf)?;
            let line = std::str::from_utf8(&line_bytes)?.trim_end_matches(['\r', '\n']);
            if line.starts_with("#fields") {
                fields = parse_fields_header(line);
            } else if format.is_none() && !line.trim().is_empty() && !line.starts_with('#') {
                format = Some(detect_format(line));
            }
            if format == Some(ZeekFormat::Json)
                || (format == Some(ZeekFormat::Tsv) && !fields.is_empty())
            {
                break;
            }
        }
        let format = format.unwrap_or(ZeekFormat::Tsv);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cutoff = now - time_window.as_secs_f64();

        let mut out = Vec::new();
        reader.seek(SeekFrom::Start(0))?;
        let mut parsed_bytes = 0_u64;
        loop {
            let bytes_read = read_bounded_line(&mut reader, &mut line_bytes, max_line_bytes)?;
            if bytes_read == 0 {
                break;
            }
            parsed_bytes = checked_zeek_bytes(parsed_bytes, bytes_read, max_file_bytes, &path_buf)?;
            let line = std::str::from_utf8(&line_bytes)?.trim_end_matches(['\r', '\n']);
            if let Some(rec) = parse_fn(line, &fields, format) {
                if rec.timestamp() < cutoff {
                    continue;
                }
                if !targets_clone.is_empty() && !rec.involves_target(&targets_clone) {
                    continue;
                }
                if out.len() >= max_records {
                    anyhow::bail!(
                        "Zeek log {} exceeds the {} matching-record limit",
                        path_buf.display(),
                        max_records
                    );
                }
                out.push(rec);
            }
        }
        Ok(out)
    })
    .await??;

    Ok(records)
}

fn checked_zeek_bytes(
    total: u64,
    bytes_read: usize,
    max_file_bytes: u64,
    path: &Path,
) -> anyhow::Result<u64> {
    let new_total = total
        .checked_add(bytes_read as u64)
        .ok_or_else(|| anyhow::anyhow!("Zeek log byte count overflow"))?;
    if new_total > max_file_bytes {
        anyhow::bail!(
            "Zeek log {} exceeds the {} byte processing limit",
            path.display(),
            max_file_bytes
        );
    }
    Ok(new_total)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_line_bytes: usize,
) -> anyhow::Result<usize> {
    line.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(line.len());
        }
        let bytes_to_consume = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let new_len = line
            .len()
            .checked_add(bytes_to_consume)
            .ok_or_else(|| anyhow::anyhow!("Zeek line length overflow"))?;
        if new_len > max_line_bytes {
            anyhow::bail!("Zeek log line exceeds the {} byte limit", max_line_bytes);
        }
        line.extend_from_slice(&available[..bytes_to_consume]);
        let found_newline = available[bytes_to_consume - 1] == b'\n';
        reader.consume(bytes_to_consume);
        if found_newline {
            return Ok(line.len());
        }
    }
}

// ---------------------------------------------------------------------------
// ZeekDataSource
// ---------------------------------------------------------------------------

/// A [`DataSource`] backed by Zeek log files on disk.
///
/// Supports both JSON-lines and TSV output formats, auto-detected per file.
pub struct ZeekDataSource {
    log_dir: PathBuf,
}

impl ZeekDataSource {
    pub fn new(log_dir: impl Into<PathBuf>) -> Self {
        Self {
            log_dir: log_dir.into(),
        }
    }
}

#[async_trait]
impl DataSource for ZeekDataSource {
    async fn load_traffic(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<TrafficRecord>> {
        let path = self.log_dir.join("conn.log");
        let target_set: HashSet<IpAddr> = targets.iter().copied().collect();
        read_log_file(&path, &target_set, time_window, parse_conn_line).await
    }

    async fn load_dns(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<DnsRecord>> {
        let path = self.log_dir.join("dns.log");
        let target_set: HashSet<IpAddr> = targets.iter().copied().collect();
        read_log_file(&path, &target_set, time_window, parse_dns_line).await
    }

    async fn load_tls(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<TlsRecord>> {
        let path = self.log_dir.join("ssl.log");
        let target_set: HashSet<IpAddr> = targets.iter().copied().collect();
        read_log_file(&path, &target_set, time_window, parse_ssl_line).await
    }
}

#[cfg(test)]
mod bounded_reader_tests {
    use super::*;

    fn temp_log(contents: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("agentsniff-zeek-{}.log", uuid::Uuid::new_v4()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn current_conn_line() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        format!(
            "{{\"ts\":{now},\"id.orig_h\":\"192.0.2.1\",\"id.resp_h\":\"198.51.100.2\",\"id.orig_p\":40000,\"id.resp_p\":443,\"proto\":\"tcp\"}}\n"
        )
    }

    #[tokio::test]
    async fn streams_valid_records_within_limits() {
        let path = temp_log(current_conn_line().as_bytes());
        let records = read_log_file_with_limits(
            &path,
            &HashSet::new(),
            Duration::from_secs(60),
            parse_conn_line,
            4096,
            1024,
            2,
        )
        .await
        .unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn rejects_oversized_lines_and_record_sets() {
        let long_path = temp_log(&[b'x'; 33]);
        let line_error = read_log_file_with_limits(
            &long_path,
            &HashSet::new(),
            Duration::from_secs(60),
            parse_conn_line,
            4096,
            32,
            2,
        )
        .await;
        std::fs::remove_file(long_path).unwrap();
        assert!(line_error.is_err());

        let line = current_conn_line();
        let records_path = temp_log(format!("{line}{line}").as_bytes());
        let record_error = read_log_file_with_limits(
            &records_path,
            &HashSet::new(),
            Duration::from_secs(60),
            parse_conn_line,
            4096,
            1024,
            1,
        )
        .await;
        std::fs::remove_file(records_path).unwrap();
        assert!(record_error.is_err());
    }

    #[test]
    fn actual_bytes_read_are_bounded_independently_of_metadata() {
        let path = Path::new("appendable.log");
        assert_eq!(checked_zeek_bytes(4, 4, 8, path).unwrap(), 8);
        assert!(checked_zeek_bytes(8, 1, 8, path).is_err());
        assert!(checked_zeek_bytes(u64::MAX, 1, u64::MAX, path).is_err());
    }
}
