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

use axum::Router;
use crate::AuthAppState;

#[inline]
pub fn router() -> Router<AuthAppState> {
    Router::new()
        .nest("/auth/authorize", authorize::router())
        .nest("/auth/keys.json", jwks::router())
}
