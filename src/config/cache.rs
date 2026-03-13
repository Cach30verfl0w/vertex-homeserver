/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use serde::Deserialize;
use std::time::Duration;
use url::Url;

#[derive(Deserialize)]
pub struct CacheConfig {
    pub url: Url,
    pub key_prefix: String,
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
}
