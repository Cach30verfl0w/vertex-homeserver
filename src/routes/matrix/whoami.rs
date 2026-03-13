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
use ruma::api::client::account::whoami::v3::{
    Request,
    Response,
};

async fn get(Ruma { body, auth_token }: Ruma<Request>) -> Ruma<Response> {
    todo!("Not implemented yet")
}

#[inline(always)]
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/v3/account/whoami", routing::get(get))
}
