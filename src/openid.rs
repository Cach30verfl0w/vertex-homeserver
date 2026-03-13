/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::AppState;
use openidconnect::{
    AdditionalProviderMetadata,
    AuthUrl,
    ClientId,
    CsrfToken,
    EndpointMaybeSet,
    EndpointNotSet,
    EndpointSet,
    IssuerUrl,
    JsonWebKeySetUrl,
    Nonce,
    PkceCodeChallenge,
    PkceCodeChallengeMethod,
    PkceCodeVerifier,
    ProviderMetadata,
    RedirectUrl,
    RegistrationUrl,
    ResponseTypes,
    RevocationUrl,
    Scope,
    TokenUrl,
    core::{
        CoreAuthDisplay,
        CoreAuthPrompt,
        CoreClaimName,
        CoreClaimType,
        CoreClient,
        CoreClientAuthMethod,
        CoreGrantType,
        CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    },
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatrixAdditionalProviderMetadata {
    // TODO: Add account management UR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<RevocationUrl>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prompt_values_supported: Vec<CoreAuthPrompt>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
}

impl AdditionalProviderMetadata for MatrixAdditionalProviderMetadata {}

pub type MatrixProviderMetadata = ProviderMetadata<
    MatrixAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

// TODO: Add all metadata information
#[derive(Deserialize, Serialize, Debug)]
pub struct AuthFlowSession {
    pub requester_client_id: ClientId,
    pub requester_redirect_url: RedirectUrl,
    pub requester_csrf_token: Option<CsrfToken>,
    pub requester_pkce_challenge: Option<PkceCodeChallenge>,
    pub requester_token_nonce: Option<Nonce>,
    pub requester_scopes: Vec<String>,
    pub homeserver_nonce: Nonce,
    pub homeserver_pkce_verifier: PkceCodeVerifier,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthCodeInfo {
    pub scopes: Vec<String>,
    pub client_id: ClientId,
    pub nonce: Option<Nonce>,
}

pub type UpstreamOAuth2Client =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

pub fn create_auth_metadata(app_state: &AppState) -> MatrixProviderMetadata {
    let base_url = &app_state.config.base_url;
    let child_url = |url: &'static str| base_url.join(url.trim_start_matches("/")).ok();

    MatrixProviderMetadata::new(
        IssuerUrl::from_url(base_url.clone()),
        AuthUrl::from_url(child_url("/_vertex/authorize").unwrap()),
        JsonWebKeySetUrl::from_url(child_url("/_vertex/keys.json").unwrap()),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::Token]),
        ],
        vec![],
        vec![CoreJwsSigningAlgorithm::None], // TODO
        MatrixAdditionalProviderMetadata {
            revocation_endpoint: child_url("/_vertex/revoke").map(|url| RevocationUrl::from_url(url)),
            code_challenge_methods_supported: vec![PkceCodeChallengeMethod::new("S256".into())],
            prompt_values_supported: vec![CoreAuthPrompt::Extension("create".into())],
        },
    )
    .set_grant_types_supported(Some(vec![CoreGrantType::AuthorizationCode, CoreGrantType::RefreshToken]))
    .set_registration_endpoint(child_url("/_vertex/register").map(|url| RegistrationUrl::from_url(url)))
    .set_token_endpoint(child_url("/_vertex/token").map(|url| TokenUrl::from_url(url)))
    .set_response_modes_supported(Some(vec![CoreResponseMode::Query, CoreResponseMode::Fragment]))
    .set_scopes_supported(Some(vec![Scope::new("openid".into()), Scope::new("email".into())]))
    .set_token_endpoint_auth_methods_supported(Some(vec![CoreClientAuthMethod::None]))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".into()), // Subject (account identifier, Matrix ID)
        CoreClaimName::new("iss".into()), // Issuer URL (Base URL)
        CoreClaimName::new("exp".into()), // Time of token expiration
        CoreClaimName::new("iat".into()), // Time of token issuing
        CoreClaimName::new("kid".into()), // ID of the key used for signing (can be verified with jwks endpoint)
        CoreClaimName::new("nbf".into()), // Start to be accepted for authentication
        CoreClaimName::new("aud".into()), // The target client of the token
    ]))
}
