/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

pub mod config;
pub mod data;
pub mod error;
pub mod routes;

use crate::{
    config::{
        JsonWebKeySetConfig,
        OAuth2Config,
    },
    data::{
        MatrixAdditionalProviderMetadata,
        MatrixProviderMetadata,
    },
};
use openidconnect::{
    AuthUrl,
    IssuerUrl,
    JsonWebKeySetUrl,
    PkceCodeChallengeMethod,
    RegistrationUrl,
    ResponseTypes,
    RevocationUrl,
    Scope,
    TokenUrl,
    core::{
        CoreAuthPrompt,
        CoreClaimName,
        CoreClientAuthMethod,
        CoreGrantType,
        CoreResponseMode,
        CoreResponseType,
    },
};
use std::sync::Arc;
use url::Url;
use vertex_common::CommonAppStateExt;

pub type AuthAppState = Arc<dyn AuthAppStateExt>;

pub trait AuthAppStateExt: CommonAppStateExt {
    fn provider_metadata(&self) -> &MatrixProviderMetadata;
}

/// Create OAuth 2.0 provider metadata for homeserver provider.
///
/// This function creates the Matrix-compatible provider metadata for the
/// intermediate provider. It reflects the implemented capabilities of this
/// auth implementation.
///
/// ## See also
/// - [GET /_matrix/client/v1/auth_metadata, Matrix Client-Server API v1.17](https://spec.matrix.org/v1.17/client-server-api/#get_matrixclientv1auth_metadata)
/// - [3. OpenID Provider Metadata, OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
pub fn create_provider_metadata(
    base_url: &Url,
    auth_config: &OAuth2Config,
) -> MatrixProviderMetadata {
    let child_url = |url: &str| base_url.join(url.trim_start_matches("/")).ok();
    let supported_keys = match &auth_config.jwks {
        JsonWebKeySetConfig::Files { list } => list.iter().map(|x| x.algorithm.clone()).collect::<Vec<_>>(),
    };

    MatrixProviderMetadata::new(
        IssuerUrl::from_url(base_url.clone()),
        AuthUrl::from_url(child_url("/_vertex/auth/authorize").unwrap()),
        JsonWebKeySetUrl::from_url(child_url("/_vertex/auth/jwks.json").unwrap()),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![],
        supported_keys,
        MatrixAdditionalProviderMetadata {
            revocation_endpoint: child_url("/_vertex/auth/revoke").map(|url| RevocationUrl::from_url(url)),
            code_challenge_methods_supported: vec![PkceCodeChallengeMethod::new("S256".into())],
            prompt_values_supported: vec![CoreAuthPrompt::Extension("create".into())],
        },
    )
    .set_grant_types_supported(Some(vec![CoreGrantType::AuthorizationCode, CoreGrantType::RefreshToken]))
    .set_registration_endpoint(child_url("/_vertex/auth/register").map(|url| RegistrationUrl::from_url(url)))
    .set_token_endpoint(child_url("/_vertex/auth/token").map(|url| TokenUrl::from_url(url)))
    .set_response_modes_supported(Some(vec![CoreResponseMode::Query, CoreResponseMode::Fragment]))
    .set_scopes_supported(Some(vec![Scope::new("openid".into())])) // TODO: Reflect scopes from upstream?
    .set_token_endpoint_auth_methods_supported(Some(vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
    ]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".into()),   // Subject (account identifier, Matrix ID)
        CoreClaimName::new("iss".into()),   // Issuer URL (Base URL)
        CoreClaimName::new("exp".into()),   // Time of token expiration
        CoreClaimName::new("iat".into()),   // Time of token issuing
        CoreClaimName::new("kid".into()),   // ID of the key used for signing (can be verified with jwks endpoint)
        CoreClaimName::new("nbf".into()),   // Start to be accepted for authentication
        CoreClaimName::new("aud".into()),   // The target client of the token
        CoreClaimName::new("scope".into()), // The scopes specifies in the authorization request
    ]))
}
