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
    ruma::Ruma,
};
use axum::{
    Router,
    routing,
};
use ruma::api::client::discovery::get_supported_versions::{
    Request,
    Response,
};

async fn get(Ruma { body: inner, .. }: Ruma<Request>) -> Ruma<Response> {
    Response::new(vec!["v1.7".into(), "v1.17".into()]).into() // Element requires a minimum version of 1.17
}

#[inline(always)]
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/versions", routing::get(get))
}
