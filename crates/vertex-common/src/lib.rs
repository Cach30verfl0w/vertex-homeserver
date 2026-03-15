/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */
use crate::error::Error;
use axum::{
    body::{
        Body,
        Bytes,
    },
    http::Method,
};
use size::Size;
use std::sync::Arc;
use url::Url;

pub mod auth;
pub mod cache;
pub mod error;
pub mod ruma;

pub type CommonAppState = Arc<dyn CommonAppStateExt>;

pub trait CommonAppStateExt: Send + Sync {
    fn get_base_url(&self) -> &Url;

    /// The maximum size of an HTTP request body. If a requester exceeds this value, the
    /// REST server returns a "payload to large" error.
    fn get_maximum_body_size(&self) -> Size;
}

/// Extracts the body bytes if the HTTP method typically carries a payload.
///
/// ## Errors
/// Returns [Error::PayloadTooLarge] if the body exceeds the limit defined in the app
/// state or if the stream fails.
pub(crate) async fn payload_bytes(
    state: &CommonAppState,
    method: Method,
    body: Body,
) -> Result<Option<Bytes>, Error> {
    if !matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        return Ok(None); // We don't process an HTTP body
    }

    let max_body_size = state.get_maximum_body_size().bytes() as _;
    axum::body::to_bytes(body, max_body_size)
        .await
        .map(|x| Some(x))
        .map_err(|_| Error::PayloadTooLarge)
}
