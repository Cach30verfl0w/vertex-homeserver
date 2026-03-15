/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

pub mod config;
pub mod redis;
pub mod memory;

use crate::error::Error;
use chrono::Duration;
use ruma::exports::serde::Serialize;
use serde::de::DeserializeOwned;

#[async_trait::async_trait]
pub trait Cache: Send + Sync {
    async fn set<K: AsRef<str> + Send, V: Serialize + Send + Sync>(
        &self,
        key: K,
        value: &V,
        ttl: Duration,
    ) -> Result<(), Error>
    where
        Self: Sized;

    async fn delete<K: AsRef<str> + Send>(
        &self,
        key: K,
    ) -> Result<(), Error>
    where
        Self: Sized;

    async fn get<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized;

    async fn get_delete<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized;
}
