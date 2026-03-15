/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */
use axum::{
    Router,
    extract::State,
    routing,
};
use figment::{
    Figment,
    providers::{
        Format,
        Yaml,
    },
};
use ruma::api::client::discovery::{
    discover_homeserver::{
        HomeserverInfo,
        Request as DiscoveryRequest,
        Response as DiscoveryResponse,
    },
    get_supported_versions::{
        Request as VersionsRequest,
        Response as VersionsResponse,
    },
};
use serde::Deserialize;
use size::Size;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::filter::LevelFilter;
use url::Url;
use vertex_auth::{
    AuthAppStateExt,
    config::AuthConfig,
    create_provider_metadata,
    data::MatrixProviderMetadata,
    service::OAuth2Service,
};
use vertex_common::{
    CommonAppState,
    CommonAppStateExt,
    cache::{
        Cache,
        config::CacheConfig,
    },
    ruma::Ruma,
};

#[derive(Deserialize)]
pub struct Config {
    base_url: Url,
    cache: CacheConfig,
    auth: AuthConfig,
}

pub struct AppState {
    config: Config,
    cache: Arc<Cache>,
    provider_metadata: MatrixProviderMetadata,
    oauth_service: Option<OAuth2Service>,
}

impl CommonAppStateExt for AppState {
    #[inline(always)]
    fn get_base_url(&self) -> &Url {
        &self.config.base_url
    }

    #[inline(always)]
    fn get_maximum_body_size(&self) -> Size {
        Size::from_megabytes(256)
    }
}

impl AuthAppStateExt for AppState {
    #[inline(always)]
    fn provider_metadata(&self) -> &MatrixProviderMetadata {
        &self.provider_metadata
    }

    #[inline(always)]
    fn get_oauth2_service(&self) -> Option<&OAuth2Service> {
        self.oauth_service.as_ref()
    }
}

async fn well_known(
    State(state): State<CommonAppState>,
    Ruma { .. }: Ruma<DiscoveryRequest>,
) -> Ruma<DiscoveryResponse> {
    DiscoveryResponse::new(HomeserverInfo::new(state.get_base_url().to_string())).into()
}

async fn versions(Ruma { .. }: Ruma<VersionsRequest>) -> Ruma<VersionsResponse> {
    VersionsResponse::new(vec!["v1.7".into(), "v1.17".into()]).into() // Element requires Matrix v1.7
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
    let config: Config = Figment::new().merge(Yaml::file("config.yaml")).extract().unwrap();
    let cache = config.cache.new_cache().await.unwrap();
    let state = AppState {
        provider_metadata: create_provider_metadata(&config.base_url, &config.auth.oauth2),
        oauth_service: OAuth2Service::new(cache.clone(), &config.auth)
            .await
            .unwrap(),
        cache,
        config,
    };

    let state = Arc::new(state);
    let router = Router::new()
        .merge(vertex_auth::routes::router())
        .with_state(state.clone())
        .route("/.well-known/matrix/client", routing::get(well_known))
        .route("/_matrix/client/versions", routing::get(versions))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:8008").await.unwrap();
    if let Err(error) = axum::serve(listener, router.into_make_service()).await {
        tracing::error!(error = %error, "Unable to start HTTP server");
    }
}
