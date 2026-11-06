#![allow(dead_code)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tinylinkd::app::{AppConfig, build_router, build_router_with_config};
use tinylinkd::db::Database;
use tinylinkd::tokens::create_token;
use tinylinkd::users::{NewUser, Role, User};
use tower::ServiceExt;

/// The socket peer address attached to every test request. Production
/// requests get this extension from `into_make_service_with_connect_info`.
pub const TEST_PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
    54321,
);

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

    pub async fn with_config(base_url: &str, trust_proxy: bool) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = Database::connect(dir.path()).await.expect("database");
        let config = AppConfig::new(
            url::Url::parse(base_url).expect("valid base URL"),
            trust_proxy,
        );
        let app = build_router_with_config(db.clone(), config);
        Self { app, db, _dir: dir }
    }

    pub async fn send(&self, mut request: Request<Body>) -> TestResponse {
        request.extensions_mut().insert(ConnectInfo(TEST_PEER));
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

    pub async fn get_with_headers(&self, uri: &str, headers: HeaderMap) -> TestResponse {
        self.request_with_headers(Method::GET, uri, None, None, headers)
            .await
    }

    pub async fn head(&self, uri: &str) -> TestResponse {
        self.request(Method::HEAD, uri, None, None).await
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
        self.request_with_headers(method, uri, token, body, HeaderMap::new())
            .await
    }

    pub async fn request_with_headers(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
        headers: HeaderMap,
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
        let mut request = builder.body(body).expect("request");
        for (name, value) in &headers {
            request.headers_mut().insert(name, value.clone());
        }
        self.send(request).await
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

/// Create a User directly in the database and an API token for them.
pub async fn create_user_with_token(
    context: &TestContext,
    username: &str,
    role: Role,
) -> (User, String) {
    let user = tinylinkd::users::create_user(
        &context.db,
        NewUser {
            username: username.into(),
            email: None,
            password: "correct horse battery staple".into(),
            role,
        },
    )
    .await
    .expect("create user");
    let token = create_token(&context.db, user.id, "test token", None)
        .await
        .expect("create token");
    (user, token.plaintext)
}

/// Create a Link through the API and return its JSON body.
pub async fn create_link(context: &TestContext, token: &str, body: Value) -> Value {
    let response = context.post("/_/api/v1/links", Some(token), body).await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

/// Create a Link with `slug` and a fixed Destination URL.
pub async fn create_link_with_slug(context: &TestContext, token: &str, slug: &str) -> Value {
    create_link(
        context,
        token,
        serde_json::json!({"destination_url": "https://example.com/destination", "slug": slug}),
    )
    .await
}
