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
        create_auth_metadata,
    },
    ruma::RumaError,
};
use aws_lc_rs::encoding::AsDer;
use axum::{
    Form,
    Json,
    Router,
    extract::State,
    http::StatusCode,
    routing,
};
use chrono::{
    DateTime,
    Duration as ChronoDuration,
    Utc,
};
use jsonwebtoken::{
    Algorithm,
    EncodingKey,
    Header,
};
use openidconnect::{
    AccessToken,
    AuthorizationCode,
    ClientId,
    EmptyExtraTokenFields,
    IdToken,
    IssuerUrl,
    JsonWebKeyId,
    Nonce,
    PkceCodeVerifier,
    RedirectUrl,
    RefreshToken,
    core::{
        CoreIdTokenFields,
        CoreTokenResponse,
        CoreTokenType,
    },
};
use pem::Pem;
use redis::AsyncTypedCommands;
use ruma::{
    OwnedUserId,
    UserId,
    api::client::{
        Error,
        error::{
            ErrorBody,
            ErrorKind,
            StandardErrorBody,
        },
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use std::{
    str::FromStr,
    time::Duration,
};

#[derive(Deserialize, Debug)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum Request {
    /// Acquire an access and refresh token from the authorization code.
    ///
    /// ## See also
    /// - [3.1.3.1. Token Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest)
    /// - [4.10.1. Token refresh flow, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#login-flow)
    AuthorizationCode {
        code: AuthorizationCode,
        redirect_uri: RedirectUrl,
        client_id: ClientId,
        code_verifier: PkceCodeVerifier,
    },

    /// Refresh the access token.
    ///
    /// ## See also
    /// - [12.1. Refresh Request, OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken)
    /// - [4.10.2. Token refresh flow, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#token-refresh-flow)
    RefreshToken {
        refresh_token: RefreshToken,
        client_id: ClientId,
    },
}

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    iss: IssuerUrl,
    sub: OwnedUserId,
    kid: JsonWebKeyId,
    aud: ClientId,
    #[serde(with = "chrono::serde::ts_seconds")]
    exp: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    iat: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    nbf: DateTime<Utc>,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
}

/// ## See also
/// - [4.10.1. Login flow, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#login-flow)
/// - [4.10.2. Token refresh flow, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#token-refresh-flow)
#[tracing::instrument(name = "POST /_vertex/token", skip_all)]
async fn post(
    State(state): State<AppState>,
    Form(request): Form<Request>,
) -> Result<Json<CoreTokenResponse>, RumaError> {
    let mut redis_client = state.redis_client.get_multiplexed_async_connection().await.unwrap();
    let Request::AuthorizationCode { code, .. } = request else {
        todo!("Not implemented yet")
    };
    let auth_code_name = format!("vertex.auth.code:{}", code.secret());
    let Some(auth_code_info) = redis_client.get_del(auth_code_name).await.ok().flatten() else {
        return Err(Error::new(
            StatusCode::UNAUTHORIZED,
            ErrorBody::Standard(StandardErrorBody::new(
                ErrorKind::Unauthorized,
                "Invalid or expired authorization code".into(),
            )),
        )
        .into());
    };

    let auth_code_info: AuthCodeInfo = serde_json::from_str(&auth_code_info).unwrap();
    let header = Header::new(Algorithm::RS256); // TODO: We want support multiple algorithms (RSA for old systems, P-256 for compatibility and Ed25519)
    let provider_metadata = create_auth_metadata(&state); // TODO: We want to store the metadata, so we don't need to produce a new metadata anytime
    let current_time = Utc::now();
    let claims = TokenClaims {
        iss: provider_metadata.issuer().clone(),
        sub: UserId::parse("@cach30verfl0w:localhost").unwrap(),
        kid: JsonWebKeyId::new("key".into()),
        aud: auth_code_info.client_id,
        iat: current_time,
        nbf: current_time,
        exp: current_time + ChronoDuration::days(30),
        scope: auth_code_info.scopes.join(" "),
        nonce: auth_code_info.nonce,
    };

    let der_data = state.rsa_key_pair.as_der().unwrap();
    let pem_data = Pem::new("PRIVATE KEY", der_data.as_ref());
    let key = EncodingKey::from_rsa_pem(pem::encode(&pem_data).as_bytes()).unwrap(); // TODO
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();

    let id_token = IdToken::from_str(&token).unwrap();
    let id_token_fields = CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {});
    let mut response = CoreTokenResponse::new(AccessToken::new(token.clone()), CoreTokenType::Bearer, id_token_fields);
    response.set_refresh_token(Some(RefreshToken::new(token)));
    response.set_expires_in(Some(&Duration::new(20, 20)));
    Ok(response.into())
}

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new().route("/", routing::post(post))
}
