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
use redis::{
    AsyncTypedCommands,
    aio::MultiplexedConnection,
};
use serde::{
    Serialize,
    de::DeserializeOwned,
};

pub struct RedisCache {
    pub(crate) connection: MultiplexedConnection,
    pub(crate) key_prefix: Option<String>,
}

#[async_trait::async_trait]
impl Cache for RedisCache {
    async fn set<K: AsRef<str> + Send, V: Serialize + Send + Sync>(
        &self,
        key: K,
        value: &V,
        ttl: Duration,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        let key = self
            .key_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{}", key.as_ref()))
            .unwrap_or(key.as_ref().to_string());

        let mut connection = self.connection.clone();
        connection
            .set_ex(&key, serde_json::to_string(value)?, ttl.num_seconds() as _)
            .await?;
        Ok(())
    }

    async fn delete<K: AsRef<str> + Send>(
        &self,
        key: K,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        let key = self
            .key_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{}", key.as_ref()))
            .unwrap_or(key.as_ref().to_string());

        let mut connection = self.connection.clone();
        connection.del(&key).await?;
        Ok(())
    }

    async fn get<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized,
    {
        let key = self
            .key_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{}", key.as_ref()))
            .unwrap_or(key.as_ref().to_string());

        let mut connection = self.connection.clone();
        let Some(value) = connection.get(&key).await? else {
            return Ok(None);
        };

        Ok(Some(serde_json::from_str(&value)?))
    }

    async fn get_delete<K: AsRef<str> + Send, V: DeserializeOwned + Send>(
        &self,
        key: K,
    ) -> Result<Option<V>, Error>
    where
        Self: Sized,
    {
        let key = self
            .key_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{}", key.as_ref()))
            .unwrap_or(key.as_ref().to_string());

        let mut connection = self.connection.clone();
        let Some(value) = connection.get_del(&key).await? else {
            return Ok(None);
        };

        Ok(Some(serde_json::from_str(&value)?))
    }
}
