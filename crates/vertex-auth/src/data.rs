/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use openidconnect::{
    AdditionalProviderMetadata,
    PkceCodeChallengeMethod,
    ProviderMetadata,
    RevocationUrl,
    core::{
        CoreAuthDisplay,
        CoreAuthPrompt,
        CoreClaimName,
        CoreClaimType,
        CoreClientAuthMethod,
        CoreGrantType,
        CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    },
};
use openidconnect::core::CoreJsonWebKeyType;
use serde::{
    Deserialize,
    Serialize,
};

/// Additional OAuth 2.0 provider metadata containing information expected by a Matrix client.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatrixAdditionalProviderMetadata {
    // TODO: Add account management URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<RevocationUrl>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prompt_values_supported: Vec<CoreAuthPrompt>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
}

impl AdditionalProviderMetadata for MatrixAdditionalProviderMetadata {}

pub type MatrixProviderMetadata = ProviderMetadata<
    MatrixAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub fn jwk_type_to_str(kind: CoreJsonWebKeyType) -> &'static str {
    match kind {
        CoreJsonWebKeyType::EllipticCurve => "elliptic curve",
        CoreJsonWebKeyType::OctetKeyPair => "octet",
        CoreJsonWebKeyType::RSA => "RSA",
        CoreJsonWebKeyType::Symmetric => "symmetric",
        _ => "unknown"
    }
}
