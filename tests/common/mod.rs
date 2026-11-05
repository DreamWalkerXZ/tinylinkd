#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tinylinkd::app::build_router;
use tinylinkd::db::Database;
use tower::ServiceExt;

pub struct TestContext {
    pub app: Router,
    pub db: Database,
    _dir: tempfile::TempDir,
}

impl TestContext {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = Database::connect(dir.path()).await.expect("database");
        let app = build_router(db.clone());
        Self { app, db, _dir: dir }
    }

    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        TestResponse {
            status,
            headers,
            body,
        }
    }

    pub async fn get(&self, uri: &str, token: Option<&str>) -> TestResponse {
        self.request(Method::GET, uri, token, None).await
    }

    pub async fn post(&self, uri: &str, token: Option<&str>, body: Value) -> TestResponse {
        self.request(Method::POST, uri, token, Some(body)).await
    }

    pub async fn delete(&self, uri: &str, token: Option<&str>) -> TestResponse {
        self.request(Method::DELETE, uri, token, None).await
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> TestResponse {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(json) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&json).expect("serialize body"))
            }
            None => Body::empty(),
        };
        self.send(builder.body(body).expect("request")).await
    }
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    pub fn content_type(&self) -> &str {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "expected JSON body, got {:?}: {error}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}
