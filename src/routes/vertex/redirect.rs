/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::{
    AppState,
    openid::{
        AuthCodeInfo,
        AuthFlowSession,
    },
    ruma::RumaError,
};
use axum::{
    Router,
    extract::{
        Query,
        State,
    },
    http::StatusCode,
    response::Redirect,
    routing,
};
use openidconnect::AuthorizationCode;
use redis::AsyncTypedCommands;
use ruma::api::client::{
    Error,
    error::{
        ErrorBody,
        ErrorKind,
        StandardErrorBody,
    },
};
use serde::Deserialize;

/// ## See also
/// - [3.1.2.1. Authentication Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Deserialize)]
struct Request {
    /// The homeserver requires the state parameter to be specified. It uses it to recognize the original client
    /// request initiating this process.
    state: String,
    code: Option<AuthorizationCode>,
    error: Option<String>,
    error_description: Option<String>,
}

/// This endpoint implements the redirect endpoint for requests to the OAuth 2.0 upstream provider. As the homeserver
/// only uses the "query" response mode, it only accepts query parameters with the information.
///
/// ## See also
/// - [3.1.2.1. Authentication Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
/// - [3.1.2. Redirection Endpoint, RFC 6749: OAuth 2.0 Auth Framework](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2)
#[tracing::instrument(name = "GET /_vertex/redirect", skip_all, fields(state = request.state))]
async fn get(
    State(state): State<AppState>,
    Query(request): Query<Request>,
) -> Result<Redirect, RumaError> {
    let mut redis_client = state.redis_client.get_multiplexed_async_connection().await.unwrap();
    let auth_session_name = format!("vertex.auth.flow:{}", request.state);
    let Some(auth_session) = redis_client.get_del(&auth_session_name).await.unwrap() else {
        tracing::debug!("No authentication flow was initiated by the requester with the state specified");
        return Err(Error::new(
            StatusCode::UNAUTHORIZED,
            ErrorBody::Standard(StandardErrorBody::new(
                ErrorKind::Unauthorized,
                "Invalid or expired authentication state".into(),
            )),
        )
        .into());
    };

    // If we get an error by the upstream OAuth 2.0 provider, we want to delegate the error to the original requester.
    let auth_session: AuthFlowSession = serde_json::from_str(&auth_session).unwrap(); // TODO
    if let Some((error, error_description)) = request.error.map(|error| (error, request.error_description)) {
        tracing::debug!(code = error, message = error_description, "Authentication with upstream provider failed");
        let mut redirect_uri = auth_session.requester_redirect_url.url().clone();
        redirect_uri.query_pairs_mut().append_pair("state", &request.state);
        redirect_uri.query_pairs_mut().append_pair("error", &error);
        if let Some(error_description) = error_description.as_ref() {
            redirect_uri
                .query_pairs_mut()
                .append_pair("error_description", error_description);
        }

        return Ok(Redirect::to(redirect_uri.as_str()));
    }

    tracing::info!("Authentication with upstream provider was successful");
    let code = request.code.unwrap(); // TODO: Return bad request when code is not present and store code in cache
    let auth_code_name = format!("vertex.auth.code:{}", code.secret());
    let code_info = serde_json::to_string(&AuthCodeInfo {
        scopes: auth_session.requester_scopes,
        client_id: auth_session.requester_client_id,
        nonce: auth_session.requester_token_nonce,
    })
    .unwrap();
    if let Err(error) = redis_client.set_ex(&auth_code_name, code_info, 30).await {
        tracing::error!(error = %error, entry_name = auth_code_name, "Unable to add cache entry for auth code");
        return Err(Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorBody::Standard(StandardErrorBody::new(
                ErrorKind::Unknown,
                "Error while processing initiated auth session".into(),
            )),
        )
        .into());
    }

    let mut redirect_uri = auth_session.requester_redirect_url.url().clone();
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", code.secret())
        .append_pair("state", auth_session.requester_csrf_token.unwrap().secret());
    Ok(Redirect::to(redirect_uri.as_str()))
}

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new().route("/", routing::get(get))
}
