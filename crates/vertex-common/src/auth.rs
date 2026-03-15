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
    CommonAppState,
    error::Error,
};
use axum::http::request::Parts;
use ruma::api::auth_scheme::{
    AccessToken,
    AccessTokenOptional,
    NoAuthentication,
};

pub trait AuthValidator {
    fn is_authenticated(
        state: &CommonAppState,
        request: &Parts,
    ) -> Result<(), Error>; // TODO: We should return info when present: Option<AuthData>
}

impl AuthValidator for NoAuthentication {
    fn is_authenticated(
        _state: &CommonAppState,
        _request: &Parts,
    ) -> Result<(), Error> {
        Ok(()) // The user doesn't need to be authenticated
    }
}

impl AuthValidator for AccessToken {
    #[tracing::instrument(name = "AccessToken::is_authenticated", skip_all)]
    fn is_authenticated(
        _state: &CommonAppState,
        _request: &Parts,
    ) -> Result<(), Error> {
        Ok(()) // TODO: Validate the access token
    }
}

impl AuthValidator for AccessTokenOptional {
    #[tracing::instrument(name = "AccessTokenOptional::is_authenticated", skip_all)]
    fn is_authenticated(
        _state: &CommonAppState,
        _request: &Parts,
    ) -> Result<(), Error> {
        Ok(()) // TODO: Validate the access token if present
    }
}
