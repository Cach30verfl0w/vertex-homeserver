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
    cache::{
        Cache,
        memory::MemoryCache,
        redis::RedisCache,
    },
    error::Error,
};
use serde::Deserialize;
use std::sync::Arc;

/// The cache used for storing short-living values.
///
/// This config specifies the type and connection info for the cache used
///  auth sessions etc.
///
/// ## Variants
/// - [CacheConfig::Memory] - The in-memory cache primarily used for testing
/// - [CacheConfig::Redis] - The Redis cache used for production setups
#[derive(Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum CacheConfig {
    Memory {
        /// The count of maximum entries allowed to be in the cache.
        max_entries: usize,
    },
    Redis {
        /// The connection url (e.g. redis://127.0.0.1:6379)
        url: String,

        /// Optional prefix for all keys to prevent collisions
        key_prefix: Option<String>,
    },
}

impl CacheConfig {
    pub async fn new_cache(&self) -> Result<Arc<Cache>, Error> {
        match self {
            Self::Memory { max_entries } => Ok(Arc::new(Cache::Memory(MemoryCache::new(*max_entries)))),
            Self::Redis { url, key_prefix } => {
                tracing::info!("Establishing connection to Redis cache");
                let client = redis::Client::open(url.as_str())?
                    .get_multiplexed_async_connection()
                    .await?;
                Ok(Arc::new(Cache::Redis(RedisCache {
                    connection: client,
                    key_prefix: key_prefix.clone(),
                })))
            }
        }
    }
}
