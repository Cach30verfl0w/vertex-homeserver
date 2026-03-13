/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

mod config;
mod openid;
mod routes;
mod ruma;

use crate::{
    config::RootConfig,
    openid::UpstreamOAuth2Client,
};
use aws_lc_rs::{
    rsa,
    rsa::KeySize,
};
use axum::http::{
    Method,
    header,
};
use openidconnect::{
    RedirectUrl,
    core::{
        CoreClient,
        CoreProviderMetadata,
    },
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::{
    cors,
    cors::CorsLayer,
};

pub struct AppStateInner {
    pub upstream_provider_metadata: CoreProviderMetadata,
    pub upstream_provider_client: UpstreamOAuth2Client,
    pub redis_client: redis::Client, // TODO: Use MultiplexedConnection
    pub config: RootConfig,
    pub rsa_key_pair: rsa::KeyPair,
}

pub type AppState = Arc<AppStateInner>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let config = RootConfig::read("./config.yaml");

    // authorize -> [state, nonce, etc.] into cache -> Weiterleitung zum Upstream -> Auth -> Redirect zum Service

    let redis_client = redis::Client::open(config.cache.url.as_str())?; // TODO: Duration etc.
    tracing::info!(cache_url = %config.cache.url, "Successfully established connection to Redis cache");

    // Read the OAuth 2.0 provider metadata from the upstream identity provider. When successfully read, the
    // endpoints are used.
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let upstream_provider_url = config.oauth2_upstream.issuer_url.clone();
    let upstream_provider_metadata = CoreProviderMetadata::discover_async(upstream_provider_url, &http_client).await?;
    let upstream_provider_client: UpstreamOAuth2Client = CoreClient::from_provider_metadata(
        upstream_provider_metadata.clone(),
        config.oauth2_upstream.client_id.clone(),
        config.oauth2_upstream.client_secret.clone(),
    )
    .set_redirect_uri(RedirectUrl::from_url(config.base_url.join("/_vertex/redirect")?));

    tracing::info!(issuer_url = %upstream_provider_metadata.issuer(), "Successfully read upstream provider metadata");

    // Configure and start the HTTP server on port 8008 on the localhost interface. It also configures CORS
    // so Element and other Matrix clients are working.
    let router = routes::router()
        .layer(
            CorsLayer::new()
                .allow_origin(cors::Any)
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .allow_methods(vec![Method::GET, Method::HEAD, Method::POST, Method::PUT]),
        )
        .with_state(AppState::new(AppStateInner {
            rsa_key_pair: rsa::KeyPair::generate(KeySize::Rsa4096)?,
            upstream_provider_metadata,
            upstream_provider_client,
            redis_client,
            config,
        }));
    tracing::info!(address = "127.0.0.1:8008", "Listening on for incoming HTTP requests...");
    if let Err(error) = axum::serve(TcpListener::bind("127.0.0.1:8008").await?, router.into_make_service()).await {
        tracing::error!("Unable to start server: {}", error);
    }

    Ok(())
}
