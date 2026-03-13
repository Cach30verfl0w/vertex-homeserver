/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

mod authorize;
mod jwks;
mod redirect;
mod register;
mod token;

use crate::AppState;
use axum::{
    Router,
    routing,
};

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/token", token::router())
        .nest("/redirect", redirect::router())
        .route("/keys.json", routing::get(jwks::get))
        .route("/authorize", routing::get(authorize::get))
        .route("/register", routing::post(register::post))
}
