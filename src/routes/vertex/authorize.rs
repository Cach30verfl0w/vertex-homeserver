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
    openid::AuthFlowSession,
    ruma::RumaError,
};
use axum::{
    extract::{
        Query,
        State,
    },
    response::Redirect,
};
use openidconnect::{
    ClientId,
    CsrfToken,
    Nonce,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    core::{
        CoreAuthenticationFlow,
        CoreResponseMode,
        CoreResponseType,
    },
};
use redis::TypedCommands;
use serde::{
    Deserialize,
    Deserializer,
};

fn deserialize_scopes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    String::deserialize(deserializer).map(|string| string.split_whitespace().map(|str| str.into()).collect())
}

/// ## See also
/// - [3.1.2.1. Authentication Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Deserialize)]
pub struct Request {
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    response_type: CoreResponseType,
    response_mode: Option<CoreResponseMode>,
    #[serde(flatten)]
    code_challenge: Option<PkceCodeChallenge>,
    nonce: Option<Nonce>,
    state: Option<CsrfToken>,
    #[serde(deserialize_with = "deserialize_scopes")]
    scope: Vec<String>,
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
pub async fn get(
    State(state): State<AppState>,
    Query(request): Query<Request>,
) -> Result<Redirect, RumaError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = state
        .upstream_provider_client
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scopes(
            state
                .config
                .oauth2_upstream
                .scopes
                .iter()
                .map(|x| Scope::new(x.clone())),
        )
        .url();

    let mut redis_client = state.redis_client.get_connection().unwrap();
    redis_client
        .set_ex(
            format!("vertex.auth.flow:{}", csrf_token.secret()),
            serde_json::to_string(&AuthFlowSession {
                requester_client_id: request.client_id,
                requester_redirect_url: request.redirect_uri,
                requester_csrf_token: request.state,
                requester_scopes: request.scope,
                requester_pkce_challenge: request.code_challenge,
                requester_token_nonce: request.nonce,
                homeserver_pkce_verifier: pkce_verifier,
                homeserver_nonce: nonce,
            })
            .unwrap(),
            5, // TODO: 5 minute TTL, should be configurable
        )
        .unwrap();
    Ok(Redirect::to(auth_url.as_str()))
}
