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
    cache::Cache,
    error::Error,
};
use chrono::Duration;
use moka::{
    Expiry,
    future::Cache as MokaCache,
};
use serde::{
    Serialize,
    de::DeserializeOwned,
};
use std::time::Instant;

#[derive(Clone)]
struct CacheEntry {
    value: serde_json::Value,
    ttl: Duration,
}

struct DynamicExpiry;

impl Expiry<String, CacheEntry> for DynamicExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<std::time::Duration> {
        value.ttl.clone().to_std().ok()
    }
}

pub struct MemoryCache(MokaCache<String, CacheEntry>);

#[async_trait::async_trait]
impl Cache for MemoryCache {
    async fn set<K: AsRef<str> + Send, V: Serialize + Send + Sync>(
        &self,
        key: K,
        value: &V,
        ttl: Duration,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        let value = serde_json::to_value(value)?;
        self.0.insert(key.as_ref().to_string(), CacheEntry { value, ttl }).await;
        Ok(())
    }

    async fn delete<K: AsRef<str> + Send>(
        &self,
        key: K,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.0.invalidate(key.as_ref()).await;
        Ok(())
    }

    async fn get<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized,
    {
        let key = key.as_ref();
        let Some(entry) = self.0.get(key).await else {
            return Ok(None);
        };

        Ok(Some(serde_json::from_value(entry.value)?))
    }

    async fn get_delete<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized,
    {
        let key = key.as_ref();
        let Some(entry) = self.0.get(key).await else {
            return Ok(None);
        };

        self.0.invalidate(key).await;
        Ok(Some(serde_json::from_value(entry.value)?))
    }
}

impl MemoryCache {
    #[inline(always)]
    pub fn new(max_capability: usize) -> Self {
        Self(
            MokaCache::builder()
                .expire_after(DynamicExpiry)
                .max_capacity(max_capability as _)
                .build(),
        )
    }
}
