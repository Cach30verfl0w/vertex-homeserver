/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
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
    /// - Specified file path for private key without PEM format
    #[error("Detected insecurity in config of JWK with id '{0}': {1}")]
    InvalidJsonWebKey(String, &'static str)
}
