use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn tld() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tld"))
}

#[test]
fn serve_fails_without_base_url() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld()
        .arg("serve")
        .env("TLD_DATA_DIR", dir.path())
        .env_remove("TLD_BASE_URL")
        .output()
        .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TLD_BASE_URL") || stderr.contains("--base-url"),
        "stderr: {stderr}"
    );
}

#[test]
fn serve_rejects_non_http_base_url() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld()
        .arg("serve")
        .env("TLD_BASE_URL", "ftp://example.com")
        .env("TLD_DATA_DIR", dir.path())
        .output()
        .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("http or https"), "stderr: {stderr}");
}

#[test]
fn migrate_creates_the_database_and_applies_migrations() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld()
        .arg("migrate")
        .env("TLD_DATA_DIR", dir.path())
        .output()
        .expect("run tld");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("tinylinkd.db").exists());
}

#[test]
fn migrate_emits_json_logs_when_configured() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld()
        .arg("migrate")
        .env("TLD_DATA_DIR", dir.path())
        .env("TLD_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("run tld");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log line");
    let json: serde_json::Value = serde_json::from_str(line).expect("json log");
    assert!(json.get("timestamp").is_some());
    assert!(json.get("level").is_some());
}

#[cfg(unix)]
#[test]
fn serve_shuts_down_gracefully_on_sigterm() {
    let dir = TempDir::new().expect("temp dir");
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        listener.local_addr().expect("local addr").port()
    };

    let mut child = tld()
        .arg("serve")
        .env("TLD_BASE_URL", format!("http://127.0.0.1:{port}"))
        .env("TLD_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("TLD_DATA_DIR", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tld serve");

    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("tld serve did not start listening on port {port}");
    }

    let kill_status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(kill_status.success(), "kill -TERM failed");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert!(status.success(), "tld serve exited with {status}");
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("tld serve did not shut down after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
