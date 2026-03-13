/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use axum::Json;
use openidconnect::{
    ClientId,
    core::{
        CoreClientMetadata,
        CoreClientRegistrationResponse,
    },
    registration::EmptyAdditionalClientRegistrationResponse,
};

pub async fn post(Json(client_metadata): Json<CoreClientMetadata>) -> Json<CoreClientRegistrationResponse> {
    // TODO: Add OAuth 2.0 dynamic client registration
    CoreClientRegistrationResponse::from_client_metadata(
        ClientId::new("oauth2.0-dynamic-client".into()),
        client_metadata,
        EmptyAdditionalClientRegistrationResponse {},
    )
    .into()
}
