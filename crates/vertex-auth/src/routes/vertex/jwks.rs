/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::AuthAppState;
use axum::{
    Json,
    Router,
    extract::State,
    http::StatusCode,
    routing,
};
use openidconnect::core::CoreJsonWebKeySet;
use ruma::api::client::{
    Error as MatrixError,
    error::{
        ErrorBody,
        ErrorKind,
        StandardErrorBody,
    },
};
use vertex_common::ruma::RumaError;

async fn get(State(state): State<AuthAppState>) -> Result<Json<CoreJsonWebKeySet>, RumaError> {
    let Some(service) = state.get_oauth2_service() else {
        return Err(MatrixError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorBody::Standard(StandardErrorBody::new(
                ErrorKind::Unrecognized,
                "This endpoint was disabled by the administrator".into(),
            )),
        )
        .into());
    };

    todo!("Not implemented yet")
}

#[inline]
pub fn router() -> Router<AuthAppState> {
    Router::new().route("/", routing::get(get))
}
