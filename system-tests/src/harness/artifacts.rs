// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunResult {
    Passed,
    Failed,
    Cancelled,
    InfrastructureError,
}

#[derive(Debug, Serialize)]
struct ArtifactManifest {
    schema_version: u8,
    run_id: String,
    created_at: String,
    redaction: Redaction,
    files: Vec<ArtifactFile>,
}

#[derive(Debug, Serialize)]
struct Redaction {
    profile: &'static str,
    secrets_scanned: bool,
    payloads_included: bool,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactFile {
    path: String,
    kind: String,
    node_id: Option<String>,
    media_type: String,
    bytes: u64,
    sha256: String,
    required: bool,
    redacted: bool,
    encrypted: bool,
    description: Option<String>,
}

pub struct RunArtifacts {
    pub run_id: String,
    pub root: PathBuf,
}

impl RunArtifacts {
    pub fn create(base: &Path, run_id: impl Into<String>) -> Result<Self> {
        let run_id = run_id.into();
        let root = base.join(&run_id);
        fs::create_dir_all(root.join("configs"))?;
        fs::create_dir_all(root.join("logs"))?;
        fs::create_dir_all(root.join("observations"))?;
        Ok(Self { run_id, root })
    }

    pub fn write_json<T: Serialize>(&self, relative: &str, value: &T) -> Result<()> {
        let path = safe_join(&self.root, relative)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_vec_pretty(value)?)
            .with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn write_text(&self, relative: &str, value: &str) -> Result<()> {
        let path = safe_join(&self.root, relative)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, value).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn finalize(&self) -> Result<()> {
        let mut paths = Vec::new();
        collect_files(&self.root, &self.root, &mut paths)?;
        paths.retain(|path| path != "artifact-manifest.json");
        paths.sort();
        let mut files = Vec::new();
        for relative in paths {
            let path = self.root.join(&relative);
            let bytes = fs::read(&path)?;
            scan_for_secrets(&relative, &bytes)?;
            files.push(ArtifactFile {
                kind: classify(&relative).to_string(),
                media_type: media_type(&relative).to_string(),
                node_id: node_from_path(&relative),
                bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
                required: matches!(
                    relative.as_str(),
                    "run.json" | "topology.json" | "events.jsonl" | "junit.xml" | "reproduce.sh"
                ),
                redacted: relative.starts_with("logs/") || relative.starts_with("configs/"),
                encrypted: false,
                description: None,
                path: relative,
            });
        }
        self.write_json(
            "artifact-manifest.json",
            &ArtifactManifest {
                schema_version: 1,
                run_id: self.run_id.clone(),
                created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
                redaction: Redaction {
                    profile: "local",
                    secrets_scanned: true,
                    payloads_included: false,
                    notes: Some(
                        "test identities and cluster secrets are redacted from uploaded artifacts"
                            .to_string(),
                    ),
                },
                files,
            },
        )
    }
}

fn scan_for_secrets(relative: &str, bytes: &[u8]) -> Result<()> {
    let lower_path = relative.to_ascii_lowercase();
    if lower_path.ends_with("identity.ed25519")
        || lower_path.ends_with("cluster.secret")
        || lower_path.ends_with("api.token")
    {
        anyhow::bail!("refusing to publish secret artifact {relative}");
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        for marker in [
            "\"private_key_hex\"",
            "private_key_hex =",
            "authorization: bearer ",
        ] {
            if text.to_ascii_lowercase().contains(marker) {
                anyhow::bail!("potential secret marker found in artifact {relative}");
            }
        }
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("unsafe artifact path {relative:?}");
    }
    Ok(root.join(path))
}

fn collect_files(root: &Path, current: &Path, output: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_files(root, &path, output)?;
        } else if entry.file_type()?.is_file() {
            output.push(
                path.strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn classify(path: &str) -> &str {
    match path {
        "run.json" => "run",
        "topology.json" => "topology",
        "events.jsonl" => "events",
        "junit.xml" => "junit",
        "failure.txt" => "failure",
        "reproduce.sh" => "reproduce",
        "compose.yaml" => "compose",
        "backend/network.json" => "network",
        "backend/volume-manifest.json" => "volume_manifest",
        _ if path.starts_with("configs/") => "config",
        _ if path.starts_with("backend/") && path.ends_with(".log") => "log",
        _ if path.starts_with("backend/") && path.ends_with(".metrics.prom") => "metrics",
        _ if path.starts_with("backend/") => "diagnostic",
        _ if path.starts_with("logs/") => "log",
        _ if path.starts_with("observations/") => "observation",
        _ => "other",
    }
}

fn media_type(path: &str) -> &str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".jsonl") {
        "application/x-ndjson"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".sh") {
        "text/x-shellscript"
    } else {
        "text/plain"
    }
}

fn node_from_path(path: &str) -> Option<String> {
    path.strip_prefix("logs/")
        .or_else(|| path.strip_prefix("configs/"))
        .and_then(|rest| rest.split('/').next())
        .map(ToString::to_string)
}
