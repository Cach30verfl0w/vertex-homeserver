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
};
use axum::{
    Json,
    Router,
    extract::State,
    routing,
};

pub async fn get(State(app_state): State<AppState>) -> Json<MatrixProviderMetadata> {
    create_auth_metadata(&app_state).into()
}

#[inline(always)]
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth_metadata", routing::get(get))
        .route("/unstable/org.matrix.msc2965/auth_metadata", routing::get(get))
}
