/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */
use std::sync::Arc;
use crate::{CommonAppStateExt, auth::AuthValidator, payload_bytes, CommonAppState};
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
    http::StatusCode,
    response::{
        IntoResponse,
        Response,
    },
};
use ruma::{
    api::{
        IncomingRequest,
        OutgoingResponse,
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

/// A wrapper for Ruma types to provide seamless integration with Axum.
///
/// [Ruma] acts as a custom extract and response handler, translating between native
/// Axum request and response types and Ruma types based on [IncomingRequest] etc.
#[derive(Debug)]
pub struct Ruma<T> {
    /// The underlying Ruma request or response type.
    pub body: T,
}

impl<T> From<T> for Ruma<T> {
    fn from(value: T) -> Self {
        Self { body: value }
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

impl<T: IncomingRequest> FromRequest<CommonAppState> for Ruma<T>
where
    T::Authentication: AuthValidator
{
    type Rejection = Ruma<MatrixError>;

    /// ## Errors
    /// - The request payload is too large
    /// - The authentication fails
    /// - Path parameters or body are malformed
    async fn from_request(
        request: Request,
        state: &CommonAppState,
    ) -> Result<Self, Self::Rejection> {
        // TODO: Implement rate limit

        let (mut parts, body) = request.into_parts();
        let body = payload_bytes(state, parts.method.clone(), body)
            .await?
            .unwrap_or(Bytes::from("{}"));
        let _ = T::Authentication::is_authenticated(state, &parts)?; // TODO: Get auth info

        let path: Path<Vec<String>> = parts.extract().await.map_err(|_error| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                ErrorBody::Standard(StandardErrorBody::new(
                    ErrorKind::InvalidParam,
                    "Failed to parse parameters".into(),
                )),
            )
        })?;

        let request = Request::builder().method(parts.method).body(body).map_err(|error| {
            tracing::error!("Failed to create request for Ruma => {error}");
            MatrixError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::Standard(StandardErrorBody::new(
                    ErrorKind::Unknown,
                    "Unexpected error while processing request".into(),
                )),
            )
        })?;

        let body = T::try_from_http_request(request, &path).map_err(|_error| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                ErrorBody::Standard(StandardErrorBody::new(ErrorKind::BadJson, "Failed to deserialize request".into())),
            )
        })?;

        Ok(Ruma { body })
    }
}
