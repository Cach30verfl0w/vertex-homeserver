/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

pub mod well_known;

use axum::{routing, Router};
use crate::AuthAppState;

#[inline(always)]
pub fn router() -> Router<AuthAppState> {
    Router::new()
        .route("/_matrix/client/v1/auth_metadata", routing::get(well_known::get))
        .route("/.well-known/openid-configuration", routing::get(well_known::get))
}
