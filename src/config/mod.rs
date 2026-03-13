/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

mod cache;
mod oauth2_upstream;

use crate::config::{
    cache::CacheConfig,
    oauth2_upstream::IdentityProvider,
};
use figment::{
    Figment,
    providers::{
        Env,
        Format,
        Yaml,
    },
};
use serde::Deserialize;
use std::path::Path;
use url::Url;

#[derive(Deserialize)] // TODO: JsonSchema
pub struct RootConfig {
    pub base_url: Url,
    pub oauth2_upstream: IdentityProvider,
    pub cache: CacheConfig,
}

impl RootConfig {
    #[inline(always)]
    pub fn read<P: AsRef<Path>>(path: P) -> Self {
        Figment::new()
            .merge(Yaml::file(path))
            .merge(Env::prefixed("VERTEX_"))
            .extract()
            .unwrap()
    }
}
