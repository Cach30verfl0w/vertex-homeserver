/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::AppState;
use axum::Router;

mod auth_metadata;
mod versions;
mod whoami;

#[inline(always)]
pub fn router() -> Router<AppState> {
    Router::new().merge(auth_metadata::router()).merge(versions::router())
}
