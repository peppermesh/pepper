// SPDX-License-Identifier: Apache-2.0

use pepper_types::ComputeJobSpec;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ComputeError {
    #[error("compute job command must not be empty")]
    EmptyCommand,
    #[error("compute job timeout must be greater than zero")]
    InvalidTimeout,
    #[error("compute job resource limits must be greater than zero")]
    InvalidResourceLimit,
    #[error("firecracker compute jobs must set rootfs_cid")]
    MissingFirecrackerRootfs,
    #[error("compute job runtime must be 'firecracker'")]
    InvalidRuntime,
    #[error("compute job type/version is unsupported")]
    InvalidTypeOrVersion,
    #[error("compute input/output path is unsafe: {0}")]
    UnsafePath(String),
    #[error("pids_max is not a guest-process limit and is not supported")]
    UnsupportedPidsLimit,
}

pub fn validate_job_spec(spec: &ComputeJobSpec) -> Result<(), ComputeError> {
    if spec
        .job_type
        .as_deref()
        .is_some_and(|value| value != "pepper.compute_job")
        || spec.version.is_some_and(|value| value != 1)
    {
        return Err(ComputeError::InvalidTypeOrVersion);
    }
    if spec.command.is_empty() || spec.command.iter().any(|part| part.contains('\0')) {
        return Err(ComputeError::EmptyCommand);
    }
    if let Some(runtime) = &spec.runtime
        && runtime != "firecracker"
    {
        return Err(ComputeError::InvalidRuntime);
    }
    if spec.rootfs_cid.is_none() {
        return Err(ComputeError::MissingFirecrackerRootfs);
    }
    let mut input_mounts = HashSet::new();
    for input in &spec.inputs {
        validate_relative_path(&input.mount)?;
        if !input_mounts.insert(input.mount.trim_start_matches('/')) {
            return Err(ComputeError::UnsafePath(input.mount.clone()));
        }
    }
    let mut output_names = HashSet::new();
    for output in &spec.outputs {
        validate_relative_path(&output.path)?;
        if output.name.is_empty()
            || output.name == "."
            || output.name == ".."
            || output.name == ".pepper-collected"
            || output.name.contains('/')
            || output.name.contains('\\')
        {
            return Err(ComputeError::UnsafePath(output.name.clone()));
        }
        if !output_names.insert(output.name.as_str()) {
            return Err(ComputeError::UnsafePath(output.name.clone()));
        }
    }
    if let Some(resources) = &spec.resources {
        if resources.pids_max.is_some() {
            return Err(ComputeError::UnsupportedPidsLimit);
        }
        if matches!(resources.timeout_seconds, Some(0)) {
            return Err(ComputeError::InvalidTimeout);
        }
        if matches!(resources.max_input_bytes, Some(0))
            || matches!(resources.max_output_bytes, Some(0))
            || matches!(resources.memory_mib, Some(0))
            || matches!(resources.cpu_millis, Some(0))
            || matches!(resources.pids_max, Some(0))
        {
            return Err(ComputeError::InvalidResourceLimit);
        }
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), ComputeError> {
    let relative = path.strip_prefix('/').unwrap_or(path);
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ComputeError::UnsafePath(path.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_runtime_values() {
        let mut spec = ComputeJobSpec {
            job_type: Some("pepper.compute_job".to_string()),
            version: Some(1),
            runtime: Some("firecracker".to_string()),
            rootfs_cid: None,
            command: vec!["true".to_string()],
            inputs: Vec::new(),
            outputs: Vec::new(),
            resources: None,
        };
        spec.rootfs_cid = Some(pepper_types::Cid::new(pepper_types::CODEC_RAW, b"rootfs"));
        validate_job_spec(&spec).expect("firecracker runtime is valid");
        spec.rootfs_cid = None;
        assert!(matches!(
            validate_job_spec(&spec),
            Err(ComputeError::MissingFirecrackerRootfs)
        ));
        spec.rootfs_cid = Some(pepper_types::Cid::new(pepper_types::CODEC_RAW, b"rootfs"));
        spec.runtime = Some("unknown".to_string());
        assert!(matches!(
            validate_job_spec(&spec),
            Err(ComputeError::InvalidRuntime)
        ));
    }
}
