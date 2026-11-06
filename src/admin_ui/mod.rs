mod auth;
mod common;
mod invites;
mod links;
mod settings;
mod users;

use axum::Router;
use axum::routing::{get, post};

use crate::app::AppState;

pub use auth::{AdminUser, SessionUser};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(auth::root))
        .route("/_/login", get(auth::login_page).post(auth::login))
        .route("/_/links", get(links::link_list).post(links::create_link))
        .route("/_/links/new", get(links::new_link_page))
        .route("/_/logout", post(auth::logout))
        .route(
            "/_/links/{id}",
            get(links::link_detail).post(links::update_link),
        )
        .route("/_/links/{id}/edit", get(links::edit_link_page))
        .route("/_/links/{id}/delete", post(links::delete_link))
        .route("/_/users", get(users::users_page))
        .route("/_/users/{id}/disable", post(users::user_disable))
        .route("/_/users/{id}/enable", post(users::user_enable))
        .route("/_/users/{id}/delete", post(users::user_delete))
        .route(
            "/_/invites",
            get(invites::invites_page).post(invites::invite_create),
        )
        .route("/_/invites/{id}/revoke", post(invites::invite_revoke))
        .route(
            "/_/settings",
            get(settings::settings_page).post(settings::settings_update),
        )
        .route("/_/static/admin.css", get(common::admin_css))
}
