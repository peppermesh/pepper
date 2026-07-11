// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

const PROTOCOL_VERSION: u64 = 1;

#[derive(Debug, Clone, Parser)]
struct Args {
    #[arg(long, default_value_t = 1024)]
    port: u32,
    #[arg(long, default_value = "/pepper_cancel")]
    cancel_file: PathBuf,
    #[arg(long, default_value = "/pepper_status")]
    status_file: PathBuf,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long, default_value = "/pepper_progress")]
    progress_file: PathBuf,
    #[arg(long, default_value = "/fc_stdout")]
    stdout_file: PathBuf,
    #[arg(long, default_value = "/fc_stderr")]
    stderr_file: PathBuf,
    #[arg(long)]
    progress: Option<String>,
    #[arg(long)]
    message: Option<String>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    if let Some(progress) = &args.progress {
        let message = args.message.as_deref().unwrap_or("");
        fs::write(&args.progress_file, format!("{progress} {message}\n"))?;
        return Ok(());
    }
    fs::write(&args.status_file, "guest-agent-ready\n")?;
    run(args)
}

#[cfg(target_os = "linux")]
fn run(args: Args) -> std::io::Result<()> {
    use std::{mem, os::fd::FromRawFd};

    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let listener = unsafe { std::fs::File::from_raw_fd(fd) };
    let address = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: args.port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    let bind_result = unsafe {
        bind(
            fd,
            &address as *const SockAddrVm as *const std::ffi::c_void,
            mem::size_of::<SockAddrVm>() as u32,
        )
    };
    if bind_result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { listen(fd, 16) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let args = std::sync::Arc::new(args);
    loop {
        let client_fd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            continue;
        }
        let mut client = unsafe { std::fs::File::from_raw_fd(client_fd) };
        let args = args.clone();
        std::thread::spawn(move || {
            let _ = handle_client(&mut client, &args);
        });
        let _ = listener.metadata();
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_args: Args) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pepper guest agent requires Linux AF_VSOCK",
    ))
}

fn handle_client(stream: &mut std::fs::File, args: &Args) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.contains(&b'\n') || buffer.len() >= 64 * 1024 {
            break;
        }
    }
    let value = serde_json::from_slice::<serde_json::Value>(&buffer).unwrap_or_default();
    let version = value
        .get("protocol_version")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let message_type = value
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let request_job_id = value.get("job_id").and_then(|value| value.as_str());
    let response = if version != PROTOCOL_VERSION {
        serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "type":"error",
            "error":"unsupported protocol_version"
        })
    } else if let Some(expected_job_id) = &args.job_id
        && request_job_id != Some(expected_job_id.as_str())
    {
        serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "type":"error",
            "error":"job_id mismatch"
        })
    } else {
        if message_type == "stream" {
            return handle_stream(stream, args);
        }
        match message_type {
            "hello" => serde_json::json!({
                "protocol_version": PROTOCOL_VERSION,
                "type":"hello_ack",
                "job_id": args.job_id,
                "status":"ready"
            }),
            "cancel" => {
                fs::write(&args.cancel_file, b"cancel\n")?;
                fs::write(&args.status_file, b"cancel-started\n")?;
                serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "type":"cancel_ack",
                    "job_id": args.job_id,
                    "phase":"cancel_started",
                    "status":"cancel-started"
                })
            }
            "status" => {
                let status = read_small_text(&args.status_file, 4096)
                    .unwrap_or_else(|| "unknown".to_string());
                let progress = read_small_text(&args.progress_file, 4096);
                serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "type":"status",
                    "job_id": args.job_id,
                    "status":status.trim(),
                    "progress": progress.as_deref().map(str::trim),
                    "heartbeat_unix_seconds": unix_seconds()
                })
            }
            "logs" => {
                let stdout_offset = value
                    .get("stdout_offset")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0) as usize;
                let stderr_offset = value
                    .get("stderr_offset")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0) as usize;
                let (stdout_chunk, stdout_next_offset) =
                    read_log_chunk(&args.stdout_file, stdout_offset);
                let (stderr_chunk, stderr_next_offset) =
                    read_log_chunk(&args.stderr_file, stderr_offset);
                serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "type":"log_chunk",
                    "job_id": args.job_id,
                    "stdout": stdout_chunk,
                    "stderr": stderr_chunk,
                    "stdout_offset": stdout_next_offset,
                    "stderr_offset": stderr_next_offset
                })
            }
            _ => serde_json::json!({
                "protocol_version": PROTOCOL_VERSION,
                "type":"error",
                "error":"unsupported message type"
            }),
        }
    };
    stream.write_all(response.to_string().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn handle_stream(stream: &mut std::fs::File, args: &Args) -> std::io::Result<()> {
    let mut stdout_offset = 0usize;
    let mut stderr_offset = 0usize;
    let mut terminal_ticks = 0u8;
    loop {
        let status =
            read_small_text(&args.status_file, 4096).unwrap_or_else(|| "unknown".to_string());
        let progress = read_small_text(&args.progress_file, 4096);
        let status_trimmed = status.trim().to_string();
        let status_message = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "type":"status",
            "job_id": args.job_id,
            "status":status_trimmed,
            "progress": progress.as_deref().map(str::trim),
            "heartbeat_unix_seconds": unix_seconds()
        });
        stream.write_all(status_message.to_string().as_bytes())?;
        stream.write_all(b"\n")?;
        let (stdout_chunk, stdout_next_offset) = read_log_chunk(&args.stdout_file, stdout_offset);
        let (stderr_chunk, stderr_next_offset) = read_log_chunk(&args.stderr_file, stderr_offset);
        stdout_offset = stdout_next_offset;
        stderr_offset = stderr_next_offset;
        if !stdout_chunk.is_empty() || !stderr_chunk.is_empty() {
            let logs = serde_json::json!({
                "protocol_version": PROTOCOL_VERSION,
                "type":"log_chunk",
                "job_id": args.job_id,
                "stdout": stdout_chunk,
                "stderr": stderr_chunk,
                "stdout_offset": stdout_offset,
                "stderr_offset": stderr_offset
            });
            stream.write_all(logs.to_string().as_bytes())?;
            stream.write_all(b"\n")?;
        }
        stream.flush()?;
        if status_trimmed.starts_with("job_exited") || status_trimmed == "cancel_completed" {
            terminal_ticks = terminal_ticks.saturating_add(1);
            if terminal_ticks >= 2 {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn read_small_text(path: &PathBuf, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn read_log_chunk(path: &PathBuf, offset: usize) -> (String, usize) {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_CHUNK: usize = 16 * 1024;
    let Ok(mut file) = fs::File::open(path) else {
        return (String::new(), offset);
    };
    let length = file
        .metadata()
        .map(|metadata| metadata.len() as usize)
        .unwrap_or(offset);
    if offset >= length || file.seek(SeekFrom::Start(offset as u64)).is_err() {
        return (String::new(), length);
    }
    let mut bytes = vec![0u8; MAX_CHUNK.min(length - offset)];
    let read = file.read(&mut bytes).unwrap_or(0);
    bytes.truncate(read);
    (
        String::from_utf8_lossy(&bytes).to_string(),
        offset.saturating_add(read),
    )
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

#[cfg(target_os = "linux")]
const AF_VSOCK: i32 = 40;
#[cfg(target_os = "linux")]
const SOCK_STREAM: i32 = 1;
#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const std::ffi::c_void, length: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, address: *mut std::ffi::c_void, length: *mut u32) -> i32;
}
