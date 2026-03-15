/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::ruma::Ruma;
use ruma::{
    api::client::error::{
        Error as MatrixError,
        ErrorBody,
        ErrorKind,
        StandardErrorBody,
    },
    exports::http::StatusCode,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP payload is too large")]
    PayloadTooLarge,

    #[error(transparent)]
    Redis(#[from] redis::RedisError),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error)
}

impl From<Error> for Ruma<MatrixError> {
    fn from(original: Error) -> Self {
        match original {
            Error::PayloadTooLarge => {
                MatrixError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorBody::Standard(StandardErrorBody::new(
                        ErrorKind::TooLarge,
                        "Content is too large to serve".into(),
                    )),
                )
            }
            _ => {
                MatrixError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorBody::Standard(StandardErrorBody::new(
                        ErrorKind::Unknown,
                        "Unexpected error while processing request".into(),
                    )),
                )
            }
        }
        .into()
    }
}
