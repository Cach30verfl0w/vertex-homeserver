/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::AuthAppState;
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
use openidconnect::{
    ClientId,
    CsrfToken,
    Nonce,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    core::{
        CoreResponseMode,
        CoreResponseType,
    },
};
use ruma::api::client::{
    Error as MatrixError,
    error::{
        ErrorBody,
        ErrorKind,
        StandardErrorBody,
    },
};
use serde::{
    Deserialize,
    Deserializer,
};
use vertex_common::ruma::RumaError;

fn deserialize_scopes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Scope>, D::Error> {
    String::deserialize(deserializer).map(|string| {
        string
            .split_whitespace()
            .map(|str| Scope::new(str.to_string()))
            .collect()
    })
}

/// ## See also
/// - [3.1.2.1. Authentication Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Deserialize)]
struct Request {
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    response_type: CoreResponseType,         // TODO
    response_mode: Option<CoreResponseMode>, // TODO
    #[serde(flatten)]
    code_challenge: Option<PkceCodeChallenge>,
    nonce: Option<Nonce>,
    state: Option<CsrfToken>,
    #[serde(deserialize_with = "deserialize_scopes")]
    scope: Vec<Scope>,
}

/// Initiates the OAuth 2.0 authorization flow by acting as an intermediate proxy.
///
/// This endpoint starts the "front-channel" part of the OAuth 2.0 flow. It preserves the
/// Matrix client's request state, generates a new PKCE challenge for the upstream
/// Identity Provider (IdP), and redirects the user's browser.
///
/// ### Process Flow:
/// 1. **State Preservation**: Stores `AuthFlowSession` in Redis (TTL: 5m) keyed by a new state token.
/// 2. **Upstream Preparation**: Generates a secondary PKCE challenge for the upstream IdP.
/// 3. **Handover**: Redirects the user to the upstream IdP's authorization page.
///
/// After the user authenticates with the IdP, the flow continues at the homeserver's `/redirect`
/// endpoint before finally returning to the Matrix client.
///
/// TODO: This endpoint should be rate-limited as it generates entries into the homeserver's cache
///
/// ## See also
/// - [3.1.2.1. Authentication Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
/// - [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
/// - [4.10. OAuth 2.0 API, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#oauth-20-api)
async fn get(
    State(state): State<AuthAppState>,
    Query(request): Query<Request>,
) -> Result<Redirect, RumaError> {
    let Some(service) = state.get_oauth2_service() else {
        return Err(MatrixError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorBody::Standard(StandardErrorBody::new(
                ErrorKind::Unrecognized,
                "This endpoint was disabled by the administrator".into(),
            )),
        )
        .into());
    };

    service
        .initiate_authorization_flow(
            request.state,
            request.client_id,
            request.scope,
            request.code_challenge,
            request.nonce,
            request.redirect_uri,
        )
        .await
        .map(|url| Redirect::temporary(url.as_str()))
        .map_err(|error| error.into())
}

#[inline]
pub fn router() -> Router<AuthAppState> {
    Router::new().route("/", routing::get(get))
}
