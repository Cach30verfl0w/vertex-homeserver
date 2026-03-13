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
        MatrixProviderMetadata,
        create_auth_metadata,
    },
    ruma::Ruma,
};
use axum::{
    Json,
    Router,
    extract::State,
    routing,
};
use ruma::api::client::discovery::discover_homeserver::{
    HomeserverInfo,
    Request as ClientDiscoverRequest,
    Response as ClientDiscoverResponse,
};

async fn matrix_client(
    State(state): State<AppState>,
    Ruma { .. }: Ruma<ClientDiscoverRequest>,
) -> Ruma<ClientDiscoverResponse> {
    ClientDiscoverResponse::new(HomeserverInfo::new(state.config.base_url.to_string())).into()
}

async fn openid_configuration(State(app_state): State<AppState>) -> Json<MatrixProviderMetadata> {
    create_auth_metadata(&app_state).into()
}

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/openid-configuration", routing::get(openid_configuration))
        .route("/matrix/client", routing::get(matrix_client))
}
