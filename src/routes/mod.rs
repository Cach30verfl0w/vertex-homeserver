/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

mod matrix;
mod vertex;
mod well_known;

use crate::AppState;
use axum::Router;

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/_vertex", vertex::router())
        .nest("/_matrix/client", matrix::router())
        .nest("/.well-known", well_known::router())
}
