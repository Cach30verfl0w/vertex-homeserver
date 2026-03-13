/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use axum::{
    RequestPartsExt,
    body::{
        Body,
        Bytes,
    },
    extract::{
        FromRequest,
        Path,
        Request,
    },
    http::{
        Method,
        Request as HttpRequest,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
};
use openidconnect::core::CoreIdToken;
use ruma::{
    api::{
        IncomingRequest,
        OutgoingResponse,
        auth_scheme::{
            AccessToken,
            AccessTokenOptional,
            NoAuthentication,
        },
        client::{
            Error as MatrixError,
            error::{
                ErrorBody,
                ErrorKind,
                StandardErrorBody,
            },
        },
    },
    exports::bytes::BytesMut,
};
use std::fmt::Debug;

pub type RumaError = Ruma<MatrixError>;

#[derive(Debug)]
pub struct Ruma<T> {
    pub body: T,
    pub auth_token: Option<CoreIdToken>,
}

impl<T> From<T> for Ruma<T> {
    fn from(value: T) -> Self {
        Ruma {
            body: value,
            auth_token: None,
        }
    }
}

impl<T: OutgoingResponse> IntoResponse for Ruma<T> {
    fn into_response(self) -> Response {
        match self.body.try_into_http_response::<BytesMut>() {
            Ok(resp) => resp.map(BytesMut::freeze).map(Body::from).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

pub trait Authenticator {
    fn is_authenticated<S, B: AsRef<[u8]>>(
        state: &S,
        request: &HttpRequest<B>,
    ) -> Result<(), MatrixError>;
}

impl Authenticator for NoAuthentication {
    fn is_authenticated<S, B: AsRef<[u8]>>(
        state: &S,
        request: &HttpRequest<B>,
    ) -> Result<(), MatrixError> {
        // The user is always authenticated
        Ok(())
    }
}

impl Authenticator for AccessToken {
    fn is_authenticated<S, B: AsRef<[u8]>>(
        state: &S,
        request: &HttpRequest<B>,
    ) -> Result<(), MatrixError> {
        todo!("Not implemented yet")
    }
}

impl Authenticator for AccessTokenOptional {
    fn is_authenticated<S, B: AsRef<[u8]>>(
        state: &S,
        request: &HttpRequest<B>,
    ) -> Result<(), MatrixError> {
        todo!("Not implemented yet")
    }
}

impl<T: IncomingRequest, S: Sync + Send> FromRequest<S> for Ruma<T>
where
    T::Authentication: Authenticator,
{
    type Rejection = RumaError;

    // TODO: Information about requesting user (address etc.) and request ID
    async fn from_request(
        request: Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // TODO: Check rate limiting

        let (mut parts, body) = request.into_parts();
        let body = match parts.method {
            Method::POST => {
                axum::body::to_bytes(body, 1024 * 1024) // TODO: Config for content limit
                    .await
                    .map_err(|error| {
                        tracing::debug!("Rejected illegal request => {error}"); // TODO: Log Level
                        MatrixError::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            ErrorBody::Standard(StandardErrorBody::new(
                                ErrorKind::TooLarge,
                                "Content is too large to serve".into(),
                            )),
                        )
                    })?
            }
            _ => Bytes::from("{}"),
        };

        let http_request = HttpRequest::from_parts(parts.clone(), body.clone());
        let _ = T::Authentication::is_authenticated(&state, &http_request)?;

        // TODO: Handle authentication

        let path: Path<Vec<String>> = parts.extract().await.map_err(|error| {
            tracing::debug!("Failed to parse path parameters => {error}"); // TODO: Log Level
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                ErrorBody::Standard(StandardErrorBody::new(
                    ErrorKind::InvalidParam,
                    "Failed to parse parameters".into(),
                )),
            )
        })?;

        let request = Request::builder().method(parts.method).body(body).map_err(|error| {
            tracing::debug!("Failed to create request for Ruma => {error}"); // TODO: Log Level
            MatrixError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::Standard(StandardErrorBody::new(
                    ErrorKind::Unknown,
                    "Unexpected error while processing request".into(),
                )),
            )
        })?;

        let request_body = T::try_from_http_request(request, &path).map_err(|error| {
            tracing::debug!("Failed to create request for Ruma => {error}"); // TODO: Log Level
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                ErrorBody::Standard(StandardErrorBody::new(ErrorKind::BadJson, "Failed to deserialize request".into())),
            )
        })?;

        Ok(Ruma {
            body: request_body,
            auth_token: None, // TODO
        })
    }
}
