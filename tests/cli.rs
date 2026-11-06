use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use sqlx::Connection;
use tempfile::TempDir;
use tower::ServiceExt;

fn tld() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tld"))
}

fn tld_command(args: &[&str], data_dir: &Path) -> Command {
    let mut command = tld();
    command.args(args).env("TLD_DATA_DIR", data_dir);
    command
}

fn tld_with_stdin(args: &[&str], data_dir: &Path, input: &str) -> std::process::Output {
    let mut command = tld_command(args, data_dir);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn tld");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("run tld")
}

#[test]
fn serve_fails_without_base_url() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld_command(&["serve"], dir.path())
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
    let output = tld_command(&["serve"], dir.path())
        .env("TLD_BASE_URL", "ftp://example.com")
        .output()
        .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("http or https"), "stderr: {stderr}");
}

#[test]
fn fatal_errors_follow_json_log_format() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld_command(&["serve"], dir.path())
        .env("TLD_BASE_URL", "ftp://example.com")
        .env("TLD_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log line");
    let json: serde_json::Value = serde_json::from_str(line).expect("json fatal log");
    assert!(json.get("level").is_some());
    assert!(stderr.contains("http or https"));
}

#[test]
fn migrate_creates_the_database_and_applies_migrations() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld_command(&["migrate"], dir.path())
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
    let output = tld_command(&["migrate"], dir.path())
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

#[tokio::test]
async fn backup_creates_a_snapshot_with_schema_and_data() {
    let dir = TempDir::new().expect("temp dir");
    let data_dir = dir.path().join("data");

    let output = tld_with_stdin(
        &["admin", "create", "--username", "backup-user"],
        &data_dir,
        "hunter2\n",
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let backup_path = dir.path().join("snapshot.db");
    let output = tld_command(
        &[
            "backup",
            "--output",
            backup_path.to_str().expect("utf8 path"),
        ],
        &data_dir,
    )
    .env_remove("TLD_BASE_URL")
    .output()
    .expect("run tld");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(backup_path.exists(), "backup file was not created");
    assert!(
        data_dir.join("tinylinkd.db").exists(),
        "backup must not move the live database"
    );

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&backup_path)
        .read_only(true);
    let mut connection = sqlx::sqlite::SqliteConnection::connect_with(&options)
        .await
        .expect("open backup");

    let username: String = sqlx::query_scalar("SELECT username FROM users")
        .fetch_one(&mut connection)
        .await
        .expect("users table in the backup");
    assert_eq!(username, "backup-user");

    let migrations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(&mut connection)
            .await
            .expect("migration history in the backup");
    assert!(migrations >= 1, "backup is missing schema migrations");

    let settings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings")
        .fetch_one(&mut connection)
        .await
        .expect("settings in the backup");
    assert_eq!(settings, 4, "backup is missing default Instance settings");

    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut connection)
        .await
        .expect("integrity check");
    assert_eq!(integrity, "ok");
}

#[test]
fn backup_refuses_to_overwrite_an_existing_output_file() {
    let dir = TempDir::new().expect("temp dir");
    let data_dir = dir.path().join("data");
    let output = tld_command(&["migrate"], &data_dir)
        .output()
        .expect("run tld");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let backup_path = dir.path().join("existing.db");
    std::fs::write(&backup_path, b"do not clobber me").expect("seed existing file");

    let output = tld_command(
        &[
            "backup",
            "--output",
            backup_path.to_str().expect("utf8 path"),
        ],
        &data_dir,
    )
    .env_remove("TLD_BASE_URL")
    .output()
    .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}");
    assert_eq!(
        std::fs::read(&backup_path).expect("read existing file"),
        b"do not clobber me",
        "backup modified an existing file"
    );
}

#[cfg(unix)]
#[test]
fn serve_shuts_down_gracefully_on_sigterm() {
    let dir = TempDir::new().expect("temp dir");
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        listener.local_addr().expect("local addr").port()
    };

    let mut child = tld_command(&["serve"], dir.path())
        .env("TLD_BASE_URL", format!("http://127.0.0.1:{port}"))
        .env("TLD_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tld serve");

    if !wait_until_health(port) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("tld serve did not become healthy on port {port}");
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

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn wait_until_health(port: u16) -> bool {
    for _ in 0..60 {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let request = format!(
                "GET /_/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = String::new();
                if stream.read_to_string(&mut response).is_ok()
                    && response.starts_with("HTTP/1.1 200")
                    && response.contains("\"status\":\"ok\"")
                {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn http_get(port: u16, path: &str, token: Option<&str>) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn admin_create_and_token_create_issue_a_working_api_token() {
    let dir = TempDir::new().expect("temp dir");

    let output = tld_with_stdin(
        &[
            "admin",
            "create",
            "--username",
            "bob",
            "--email",
            "bob@example.com",
        ],
        dir.path(),
        "hunter2\n",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("hunter2"),
        "password was echoed"
    );
    assert!(!stderr.contains("hunter2"), "password was logged: {stderr}");

    let output = tld_command(
        &["token", "create", "--user", "bob", "--name", "ci token"],
        dir.path(),
    )
    .output()
    .expect("run tld");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    let token = String::from_utf8(output.stdout)
        .expect("utf8 token")
        .trim()
        .to_string();
    assert!(token.starts_with("tld_"), "{token}");
    assert!(!stderr.contains(&token), "token was logged: {stderr}");

    let db = tinylinkd::db::Database::connect(dir.path())
        .await
        .expect("database");
    let app = tinylinkd::app::build_router(db);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/_/api/v1/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(profile["username"], "bob");
    assert_eq!(profile["role"], "admin");
    assert_eq!(profile["email"], "bob@example.com");
}

#[test]
fn token_create_rejects_an_unknown_user() {
    let dir = TempDir::new().expect("temp dir");

    let output = tld_command(&["token", "create", "--user", "ghost"], dir.path())
        .output()
        .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found"), "stderr: {stderr}");
}

#[test]
fn token_create_rejects_an_invalid_expiry() {
    let dir = TempDir::new().expect("temp dir");
    let output = tld_with_stdin(
        &["admin", "create", "--username", "bob"],
        dir.path(),
        "hunter2\n",
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = tld_command(
        &[
            "token",
            "create",
            "--user",
            "bob",
            "--expires-at",
            "tomorrow",
        ],
        dir.path(),
    )
    .output()
    .expect("run tld");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RFC 3339"), "stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn serve_bootstraps_the_first_admin_from_environment() {
    let dir = TempDir::new().expect("temp dir");
    let port = free_port();
    let child = tld_command(&["serve"], dir.path())
        .env("TLD_BASE_URL", format!("http://127.0.0.1:{port}"))
        .env("TLD_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("TLD_BOOTSTRAP_ADMIN_USERNAME", "boot")
        .env("TLD_BOOTSTRAP_ADMIN_PASSWORD", "boot password")
        .env("TLD_BOOTSTRAP_ADMIN_EMAIL", "boot@example.com")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tld serve");
    let mut child = ChildGuard(child);

    if !wait_until_health(port) {
        panic!("tld serve did not become healthy on port {port}");
    }

    let output = tld_command(&["token", "create", "--user", "boot"], dir.path())
        .output()
        .expect("run tld token create");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let token = String::from_utf8(output.stdout)
        .expect("utf8 token")
        .trim()
        .to_string();

    let response = http_get(port, "/_/api/v1/me", Some(&token));
    assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
    assert!(response.contains("\"username\":\"boot\""), "{response}");
    assert!(response.contains("\"role\":\"admin\""), "{response}");
    assert!(
        response.contains("\"email\":\"boot@example.com\""),
        "{response}"
    );

    let _ = child.0.kill();
    let _ = child.0.wait();
}
