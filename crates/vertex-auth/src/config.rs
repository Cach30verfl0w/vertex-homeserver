/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::error::Error;
use openidconnect::{AsyncHttpClient, ClientId, ClientSecret, IssuerUrl, core::{
    CoreClientAuthMethod,
    CoreJwsSigningAlgorithm,
    CoreProviderMetadata,
}, Scope};
use serde::{
    Deserialize,
    Deserializer,
    de::Error as SerdeDeError,
};
use std::{
    ops::Deref,
    path::PathBuf,
};
use chrono::Duration;

fn default_client_auth_method() -> CoreClientAuthMethod {
    CoreClientAuthMethod::ClientSecretBasic
}

/// The OAuth 2.0 upstream provider used for authentication.
///
/// TODO: Add support for discovery validation like strict (validating issuer URL etc. according the requirements) and
///       loose
///
/// This config specifies information for using a (third-party) provider when
/// authenticating as the homeserver doesn't provide an OAuth 2.0 provider by
/// itself.
#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct UpstreamProviderConfig {
    /// The base URL of the OpenID Connect or OAuth 2.0 provider.
    ///
    /// When the upstream provider is contacted, this URL is used to extract the
    /// upstream provider metadata.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub issuer_url: IssuerUrl,

    /// The client ID of the authentication service on the upstream provider.
    ///
    /// When delegating requests to the upstream provider (a.e. if a requester inits
    /// an auth flow), this client ID is used.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub client_id: ClientId,

    /// The client's secret if the client is created as a private client.
    ///
    /// When the user authentication flow is nearly finished, this provider requests
    /// endpoints requiring secrets when this is a private client.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub client_secret: Option<ClientSecret>,

    /// The auth method for the client used if a secret is specified.
    ///
    /// When a client secret is defined, this field specifies how the client specifies
    /// the token for authenticating itself.
    #[serde(default = "default_client_auth_method")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    #[cfg_attr(
        feature = "schemars",
        schemars(regex(pattern = "^(client_secret_basic|client_secret_post|none)"))
    )]
    pub client_auth_method: CoreClientAuthMethod,

    /// The scopes used when redirecting to the upstream provider's auth endpoint.
    ///
    /// When a user is being redirected to the upstream provider for authorization, this
    /// provider specifies these scopes in the query parameters.
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    pub scopes: Vec<Scope>,
}

impl UpstreamProviderConfig {
    /// Request the upstream provider metadata with the specified HTTP client.
    ///
    /// ## See also
    /// - [3. OpenID Provider Metadata, OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
    pub async fn get_provider_metadata<'a, C: AsyncHttpClient<'a>>(
        &self,
        http_client: &'a C,
    ) -> Result<CoreProviderMetadata, Error> {
        CoreProviderMetadata::discover_async(self.issuer_url.clone(), http_client)
            .await
            .map_err(|_| Error::OAuth2DiscoveryFailed)
    }
}

const fn default_auth_flow_metadata_ttl() -> Duration {
    Duration::seconds(5)
}

const fn default_auth_code_metadata_ttl() -> Duration {
    Duration::seconds(30)
}

const fn default_access_token_ttl() -> Duration {
    Duration::hours(1)
}

const fn default_refresh_token_ttl() -> Duration {
    Duration::days(30)
}

/// The Time-to-live configuration for cache entries and tokens.
///
/// This config specifies the time-to-live values for entries temporarily stored in
/// the cache or tokens (e.g. refresh token) issued by the homeserver provider.
#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct TimeToLiveConfig {
    /// The TTL of the authentication flow metadata in the cache.
    ///
    /// This info is created when the user sends a request to the authorization endpoint
    /// and deleted when the user requests the endpoint in the `redirect_uri`.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    #[serde(
        default = "default_auth_flow_metadata_ttl",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub auth_flow_metadata: Duration,

    /// The TTL of the authentication code metadata in the cache.
    ///
    /// This info is created when the user requests th#[serde_as]e endpoint in the `redirect_uri` and
    /// is being deleted when the user calls the OAuth 2.0 token endpoint.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    #[serde(
        default = "default_auth_code_metadata_ttl",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub auth_code_metadata: Duration,

    /// The TTL of an access token issued by the homeserver auth provider.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    #[serde(
        default = "default_access_token_ttl",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub access_token: Duration,

    /// The TTL of an refresh token issued by the homeserver auth provider.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    #[serde(
        default = "default_refresh_token_ttl",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub refresh_token: Duration,
}

impl Default for TimeToLiveConfig {
    fn default() -> Self {
        Self {
            auth_flow_metadata: default_auth_flow_metadata_ttl(),
            auth_code_metadata: default_auth_code_metadata_ttl(),
            refresh_token: default_refresh_token_ttl(),
            access_token: default_access_token_ttl(),
        }
    }
}

/// Configure one JSON web key for the intermediate provider's signing.
#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct JsonWebKeyConfig {
    pub id: String,

    /// The signing algorithm used for this key.
    ///
    /// The algorithm used for singing tokens issued by the intermediate
    /// provider. Insecure values (e.g. none) are not supported.
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub algorithm: CoreJwsSigningAlgorithm,

    /// The path to the private key PEM file.
    pub file: PathBuf,
}

#[derive(Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct VerifiedJsonWebKeyConfig(JsonWebKeyConfig);

impl<'de> Deserialize<'de> for VerifiedJsonWebKeyConfig {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::try_from(JsonWebKeyConfig::deserialize(deserializer)?).map_err(|error| D::Error::custom(error))?)
    }
}

impl TryFrom<JsonWebKeyConfig> for VerifiedJsonWebKeyConfig {
    type Error = Error;

    fn try_from(config: JsonWebKeyConfig) -> Result<Self, Self::Error> {
        if config.algorithm == CoreJwsSigningAlgorithm::None {
            return Err(Error::InvalidJsonWebKey(config.id, "JWS signing algorithm 'none' is not recommended!"));
        }

        Ok(Self(config))
    }
}

impl Deref for VerifiedJsonWebKeyConfig {
    type Target = JsonWebKeyConfig;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The config section for the intermediate provider's keys for
/// signing tokens.
///
/// The JSON Web Key Set configured in this configuration is used for signing
/// the tokens (Json Web Tokens) issued by the intermediate provider.
#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum JsonWebKeySetConfig {
    Files { list: Vec<VerifiedJsonWebKeyConfig> },
}

impl JsonWebKeySetConfig {
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Files { list } => list.is_empty(),
        }
    }
}

/// The config section for the OAuth 2.0 Next-Gen Auth integration.
///
/// This config provides toggling and configuration options for the integration
/// of the OAuth 2.0 Next-Generation Auth supported since Matrix v1.15.
#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct OAuth2Config {
    #[serde(default)]
    pub enabled: bool,

    /// The JSON web key set configuration for the Matrix homeserver provider.
    ///
    /// This is the subsection to configure the JWK set for signing the tokens issued
    /// by the homeserver. This option is only none when enabled is false.
    pub jwks: Option<JsonWebKeySetConfig>,

    /// The upstream OAuth 2.0 provider for the Matrix homeserver provider.
    ///
    /// This is the subsection to configure the meta-info for using that provider
    /// as upstream. This option is only none when enabled is false.
    pub provider: Option<UpstreamProviderConfig>,

    /// The time-to-live values for cache entries and issued tokens.
    #[serde(default)]
    pub ttl: TimeToLiveConfig,
}

#[derive(Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct VerifiedOAuth2Config(OAuth2Config);

impl<'de> Deserialize<'de> for VerifiedOAuth2Config {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::try_from(OAuth2Config::deserialize(deserializer)?).map_err(|error| D::Error::custom(error))?)
    }
}

impl TryFrom<OAuth2Config> for VerifiedOAuth2Config {
    type Error = Error;

    fn try_from(config: OAuth2Config) -> Result<Self, Self::Error> {
        if config.enabled && config.provider.is_none() {
            return Err(Error::InvalidOAuth2Config("OAuth 2.0 auth is enabled, but missing upstream provider config"));
        }

        if config.enabled && config.jwks.as_ref().map(|x| x.is_empty()).unwrap_or(false) {
            return Err(Error::InvalidOAuth2Config("OAuth 2.0 auth is enabled, but missing Json Web Key Set config"));
        }

        Ok(Self(config))
    }
}

impl Deref for VerifiedOAuth2Config {
    type Target = OAuth2Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct AuthConfig {
    pub oauth2: VerifiedOAuth2Config,
}
