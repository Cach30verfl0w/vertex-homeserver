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
    config::{
        AuthConfig,
        TimeToLiveConfig,
        UpstreamProviderConfig,
    },
    error::Error,
};
use openidconnect::{
    AuthorizationCode,
    ClientId,
    CsrfToken,
    EndpointMaybeSet,
    EndpointNotSet,
    EndpointSet,
    Nonce,
    PkceCodeChallenge,
    PkceCodeVerifier,
    RedirectUrl,
    Scope,
    core::{
        CoreAuthenticationFlow,
        CoreClient,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use std::sync::Arc;
use url::Url;
use vertex_common::cache::Cache;

type UpstreamOAuth2Client =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

#[derive(Serialize, Deserialize)]
struct AuthFlowData {
    request_csrf_token: Option<CsrfToken>,
    request_client_id: ClientId,
    request_scopes: Vec<Scope>,
    request_challenge: Option<PkceCodeChallenge>,
    request_nonce: Option<Nonce>,
    request_redirect_uri: RedirectUrl,
    homeserver_pkce_verifier: PkceCodeVerifier,
    homeserver_nonce: Nonce,
}

pub enum RedirectUrlContent {
    AuthorizationCode(AuthorizationCode),
    Error {
        error_code: String,
        error_description: Option<String>,
    },
}

pub struct OAuth2Service {
    cache: Arc<Cache>,
    time_to_live_config: TimeToLiveConfig,
    upstream_provider_config: UpstreamProviderConfig,
    upstream_provider_client: UpstreamOAuth2Client
}

impl OAuth2Service {
    #[tracing::instrument(name = "OAuth2Service::new", skip_all)]
    pub async fn new(
        cache: Arc<Cache>,
        config: &AuthConfig,
    ) -> Result<Option<Self>, Error> {
        if !config.oauth2.enabled {
            tracing::debug!("Skipping OAuth 2.0 service: OAuth 2.0 Next-Gen Auth is disabled!");
            return Ok(None);
        }

        // Read upstream provider config and metadata.
        let http_client = openidconnect::reqwest::Client::builder().build()?;
        let upstream_provider_config = config.oauth2.provider.clone().unwrap();
        let upstream_provider_metadata = upstream_provider_config.get_provider_metadata(&http_client).await?;
        tracing::debug!(issuer_url = %upstream_provider_metadata.issuer(), "Loaded upstream metadata provider");

        // Read Json Web keys and initialize set.
        let json_web_keys_config = config.oauth2.jwks.as_ref().unwrap();
        // TODO: implement

        // Return.
        Ok(Some(Self {
            cache,
            time_to_live_config: config.oauth2.ttl.clone(),
            upstream_provider_client: CoreClient::from_provider_metadata(
                upstream_provider_metadata,
                upstream_provider_config.client_id.clone(),
                upstream_provider_config.client_secret.clone(),
            ),
            upstream_provider_config,
        }))
    }

    /// Initiate a new OAuth 2.0 authorization flow.
    ///
    /// This function initiates a new OAuth 2.0 authorization flow by creating
    /// a new authorization URL that redirects to the upstream provider. After
    /// that, it stores some short-living auth flow session info.
    pub async fn initiate_authorization_flow(
        &self,
        request_csrf_token: Option<CsrfToken>,
        request_client_id: ClientId,
        request_scopes: Vec<Scope>,
        request_challenge: Option<PkceCodeChallenge>,
        request_nonce: Option<Nonce>,
        request_redirect_uri: RedirectUrl,
    ) -> Result<Url, Error> {
        let (pkce_challenge, homeserver_pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, homeserver_nonce) = self
            .upstream_provider_client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
            .add_scopes(self.upstream_provider_config.scopes.iter().cloned())
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.cache
            .set(
                format!("auth.flow:{}", csrf_token.secret()),
                self.time_to_live_config.auth_flow_metadata,
                &AuthFlowData {
                    request_csrf_token,
                    request_client_id,
                    request_scopes,
                    request_challenge,
                    request_nonce,
                    request_redirect_uri,
                    homeserver_pkce_verifier,
                    homeserver_nonce,
                },
            )
            .await?;
        Ok(auth_url)
    }

    pub async fn finalize_authorization_flow(
        &self,
        csrf_token: CsrfToken,
        content: RedirectUrlContent,
    ) -> Result<Url, Error> {
        let session_key = format!("auth.flow:{}", csrf_token.secret());
        let Some(auth_flow_data): Option<AuthFlowData> = self.cache.get_and_delete(session_key).await? else {
            return Err(Error::NoAuthenticationFlow(csrf_token.secret().clone()));
        };

        let authorization_code = match content {
            RedirectUrlContent::AuthorizationCode(code) => code,
            RedirectUrlContent::Error {
                error_code,
                error_description,
            } => {
                let mut redirect_uri = auth_flow_data.request_redirect_uri.url().clone();
                redirect_uri.query_pairs_mut().append_pair("error", &error_code);
                if let Some(description) = error_description.as_ref() {
                    redirect_uri
                        .query_pairs_mut()
                        .append_pair("error_description", description);
                }

                if let Some(csrf_token) = auth_flow_data.request_csrf_token.as_ref() {
                    redirect_uri.query_pairs_mut().append_pair("state", csrf_token.secret());
                }

                return Ok(redirect_uri);
            }
        };

        // TODO: Create temporary auth code session and store in cache
        let mut redirect_uri = auth_flow_data.request_redirect_uri.url().clone();
        redirect_uri
            .query_pairs_mut()
            .append_pair("code", authorization_code.secret());
        if let Some(csrf_token) = auth_flow_data.request_csrf_token.as_ref() {
            redirect_uri.query_pairs_mut().append_pair("state", csrf_token.secret());
        }

        Ok(redirect_uri)
    }
}
