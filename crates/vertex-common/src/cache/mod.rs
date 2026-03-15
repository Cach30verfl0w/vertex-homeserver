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
pub mod memory;
pub mod redis;

use crate::error::Error;
use chrono::Duration;
use ruma::exports::serde::Serialize;
use serde::de::DeserializeOwned;
use crate::cache::memory::MemoryCache;
use crate::cache::redis::RedisCache;

pub enum Cache {
    Redis(RedisCache),
    Memory(MemoryCache)
}

impl Cache {
    pub async fn set<K: AsRef<str> + Send, V: Serialize + Send + Sync>(
        &self,
        key: K,
        ttl: Duration,
        value: &V,
    ) -> Result<(), Error> {
        match self {
            Self::Memory(cache) => cache.set(key, value, ttl).await,
            Self::Redis(cache) => cache.set(key, value, ttl).await
        }
    }

    pub async fn delete<K: AsRef<str> + Send>(
        &self,
        key: K,
    ) -> Result<(), Error> {
        match self {
            Self::Memory(cache) => cache.delete(key).await,
            Self::Redis(cache) => cache.delete(key).await
        }
    }

    pub async fn get<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error> {
        match self {
            Self::Memory(cache) => cache.get(key).await,
            Self::Redis(cache) => cache.get(key).await
        }
    }

    pub async fn get_and_delete<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error> {
        match self {
            Self::Memory(cache) => cache.get_and_delete(key).await,
            Self::Redis(cache) => cache.get_and_delete(key).await
        }
    }
}
