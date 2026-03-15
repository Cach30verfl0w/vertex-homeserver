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
    AuthAppState,
    data::MatrixProviderMetadata,
};
use axum::{
    Json,
    extract::State,
};

pub(crate) async fn get(State(state): State<AuthAppState>) -> Json<MatrixProviderMetadata> {
    state.provider_metadata().clone().into()
}
