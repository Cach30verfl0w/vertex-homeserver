/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use axum::http::StatusCode;
use ruma::api::client::{
    Error as MatrixError,
    error::{
        ErrorBody,
        ErrorKind,
        StandardErrorBody,
    },
};
use thiserror::Error;
use vertex_common::ruma::RumaError;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] openidconnect::reqwest::Error),

    #[error(transparent)]
    Common(#[from] vertex_common::error::Error),
    
    #[error(transparent)]
    Io(#[from] std::io::Error),
    
    #[error("The file is not in the PEM format")]
    Pem(#[from] pem::PemError),
    
    #[error("The key in the file was rejected")]
    AwsLc(#[from] aws_lc_rs::error::KeyRejected),

    #[error("Unexpected error while requesting upstream provider metadata")]
    OAuth2DiscoveryFailed,

    /// The configuration of a JSON web key is insecure or invalid.
    ///
    /// This error is returned when the standard security requirements
    /// for a JSON web key are not met or invalid arguments are
    /// specified.
    ///
    /// ## Cases
    /// - Use of insecure JWT signing algorithms like 'none'
    /// - Specified file path for a private key without PEM format
    #[error("Detected insecurity in config of JWK with id '{0}': {1}")]
    InvalidJsonWebKey(String, &'static str),

    /// The OAuth 2.0 Next-Gen auth configuration is invalid.
    ///
    /// This error is returned when the Next-Gen auth was enabled, but
    /// no provider or JWK set is configured.
    #[error("Detected invalid OAuth2 configuration: {0}")]
    InvalidOAuth2Config(&'static str),

    /// The OAuth 2.0 authorization session is invalid or expired.
    ///
    /// This error is returned when finalizing an authorization by being
    /// redirected to the redirect URL of the homeserver provider and the
    /// token can't be found in the cache.
    #[error("Invalid or expired authorization session '{0}'")]
    NoAuthenticationFlow(String),
    
    #[error("Unsupported algorithm for Json Web Key '{0}'")]
    UnsupportedKeyAlgorithm(String),
}

impl From<Error> for RumaError {
    fn from(original: Error) -> Self {
        match original {
            Error::Common(error) => error.into(),
            Error::NoAuthenticationFlow(_) => MatrixError::new(
                StatusCode::BAD_REQUEST,
                ErrorBody::Standard(StandardErrorBody::new(
                    ErrorKind::BadState,
                    "Invalid or expired authentication session".into(),
                )),
            ).into(),
            _ => {
                MatrixError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorBody::Standard(StandardErrorBody::new(
                        ErrorKind::Unknown,
                        "Unexpected error while processing request".into(),
                    )),
                )
            }.into()
        }
    }
}
