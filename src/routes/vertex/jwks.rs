/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Cedric Hammes
 */

use crate::AppState;
use aws_lc_rs::{
    rsa,
    signature::{
        EcdsaPublicKey,
        KeyPair,
    },
};
use axum::{
    Json,
    extract::State,
};
use openidconnect::{
    JsonWebKeyId,
    JsonWebKeySet,
    core::{
        CoreJsonCurveType,
        CoreJsonWebKey,
    },
};

fn jwk_from_rsa(
    kid: Option<JsonWebKeyId>,
    public_key: &rsa::PublicKey,
) -> CoreJsonWebKey {
    let modulus = public_key.modulus().big_endian_without_leading_zero().to_vec();
    let exponent = public_key.exponent().big_endian_without_leading_zero().to_vec();
    CoreJsonWebKey::new_rsa(modulus, exponent, kid)
}

fn jwk_from_ec(
    kid: Option<JsonWebKeyId>,
    curve: CoreJsonCurveType,
    public_key: &EcdsaPublicKey,
) -> CoreJsonWebKey {
    let bytes = public_key.as_ref();
    assert!(bytes.len() == 65 || bytes[0] == 0x04, "Illegal format for public key bytes");
    CoreJsonWebKey::new_ec(bytes[1..33].to_vec(), bytes[33..65].to_vec(), curve, kid)
}

pub async fn get(State(state): State<AppState>) -> Json<JsonWebKeySet<CoreJsonWebKey>> {
    // TODO: Load the Json Web Key Set from the internal services
    JsonWebKeySet::new(vec![jwk_from_rsa(
        Some(JsonWebKeyId::new("key".into())),
        state.rsa_key_pair.public_key(),
    )])
    .into()
}
