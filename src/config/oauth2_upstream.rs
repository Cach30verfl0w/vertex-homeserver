/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use openidconnect::{
    ClientId,
    ClientSecret,
    IssuerUrl,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct IdentityProvider {
    pub issuer_url: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: Option<ClientSecret>,
    pub scopes: Vec<String>,
}
