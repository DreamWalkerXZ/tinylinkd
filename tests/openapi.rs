mod common;

use axum::http::StatusCode;
use common::TestContext;

#[tokio::test]
async fn openapi_document_covers_auth_and_token_routes() {
    let context = TestContext::new().await;

    let response = context.get("/_/api/openapi.json", None).await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.content_type().starts_with("application/json"),
        "content type: {}",
        response.content_type()
    );
    let document = response.json();
    assert_eq!(document["openapi"], "3.1.0");
    for path in [
        "/_/api/v1/me",
        "/_/api/v1/tokens",
        "/_/api/v1/tokens/{id}",
        "/_/api/v1/links",
        "/_/api/v1/links/{id}",
        "/_/api/v1/invites",
        "/_/api/v1/invites/{id}",
        "/_/api/v1/invites/{token}",
        "/_/api/v1/invites/{token}/accept",
        "/_/api/v1/users/{id}/password-reset",
        "/_/api/v1/password-resets/{token}",
        "/_/api/v1/password-resets/{token}/accept",
    ] {
        assert!(
            document["paths"].get(path).is_some(),
            "missing path {path}: {document}"
        );
    }
    assert!(document["paths"]["/_/api/v1/me"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/tokens"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/tokens"]["post"].is_object());
    assert!(document["paths"]["/_/api/v1/tokens/{id}"]["delete"].is_object());
    assert!(document["paths"]["/_/api/v1/links"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/links"]["post"].is_object());
    assert!(document["paths"]["/_/api/v1/links/{id}"]["get"].is_object());
    assert!(
        document["components"]["schemas"]
            .get("LinkResponse")
            .is_some(),
        "missing LinkResponse schema: {document}"
    );
    assert!(document["paths"]["/_/api/v1/invites"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/invites"]["post"].is_object());
    assert!(document["paths"]["/_/api/v1/invites/{id}"]["delete"].is_object());
    assert!(document["paths"]["/_/api/v1/invites/{token}"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/invites/{token}/accept"]["post"].is_object());
    assert!(document["paths"]["/_/api/v1/users/{id}/password-reset"]["post"].is_object());
    assert!(document["paths"]["/_/api/v1/password-resets/{token}"]["get"].is_object());
    assert!(document["paths"]["/_/api/v1/password-resets/{token}/accept"]["post"].is_object());
    assert_eq!(
        document["components"]["securitySchemes"]["bearerAuth"]["type"],
        "http"
    );
    assert_eq!(
        document["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );

    insta::assert_snapshot!(
        "openapi",
        serde_json::to_string_pretty(&document).expect("pretty JSON")
    );
}
