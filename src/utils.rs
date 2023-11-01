// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::response::{IntoResponse, Response};
use axum::{extract::State, Json};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto_zkp::bn254::{
    zk_login::{JwkId, JWK},
    zk_login_api::ZkLoginEnv,
};
use parking_lot::RwLock;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;use std::{collections::HashMap, sync::Arc};
use sui_sdk::SuiClientBuilder;
use sui_types::committee::EpochId;
use tracing::info;

/// Application state that contains the JWKs
#[derive(Clone, Debug)]
pub struct AppState {
    /// Latest JWKs stored in a mapping from (iss, kid) -> JWK.
    pub jwks: Arc<RwLock<HashMap<JwkId, JWK>>>,
}

/// Response for whether a zkLogin signature is verified.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// The salt value represented as a BigInt
    pub is_verified: bool,
}

/// Enum for verify errors.
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// Failed to verify the signature.
    GenericError(String),
    /// Failed to parse something in payload.
    ParsingError,
    /// Failed to get epoch from sui client.
    GetEpochError,
    /// Failed to derive address.
    AddressDeriveError,
}

impl IntoResponse for VerifyError {
    /// Parse the error into a response.
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            VerifyError::GenericError(e) => (StatusCode::BAD_REQUEST, e),
            VerifyError::ParsingError => (StatusCode::BAD_REQUEST, "Parsing error".to_string()),
            VerifyError::GetEpochError => (StatusCode::BAD_REQUEST, "Cannot get epoch".to_string()),
            VerifyError::AddressDeriveError => {
                (StatusCode::BAD_REQUEST, "Address derive error".to_string())
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, VerifyError> {
    info!("verify called {:?}", payload);

    let network = payload.network.unwrap_or_default();
    let (url, env) = network.get_params();

    // Use payload.curr_epoch if provided, otherwise fetch current epoch
    // from payload.network (default to Mainnet if not provided).
    let curr_epoch = match payload.curr_epoch {
        Some(curr_epoch) => curr_epoch,
        None => {
            let sui_client = SuiClientBuilder::default()
                .build(url)
                .await
                .map_err(|_| VerifyError::GetEpochError)?;

            sui_client
                .governance_api()
                .get_latest_sui_system_state()
                .await
                .map_err(|_| VerifyError::GetEpochError)?
                .epoch
        }
    };
    let params = AdditionalParams {
        curr_epoch,
        jwks: state.jwks.read().clone(),
        env,
    };
    info!("params: {:?}", params);
    let bytes = Base64::decode(&payload.bytes).map_err(|_| VerifyError::ParsingError)?;
    let sig_bytes = Base64::decode(&payload.signature).map_err(|_| VerifyError::ParsingError)?;
    match verify_message(&bytes, &sig_bytes, payload.intent_scope, params) {
        Ok(_) => Ok(Json(VerifyResponse { is_verified: true })),
        Err(e) => Err(e),
    }
}

/// Request payload used to verify a zkLogin signature.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// The Base64 encoded zkLogin signature.
    pub signature: String,
    /// The Base64 encoded bytes of payload.
    pub bytes: String,
    /// The intent scope, can be either TransactionData or PersonalMessage.
    /// This determines how the `bytes` is deserialized.
    pub intent_scope: IntentScope,
    /// The network to verify the signature against. This determines the
    /// ZkLoginEnv.
    pub network: Option<SuiEnv>,
    /// The current epoch to verify the signature against. If not provided,
    /// use `network` to construct a Sui client and fetch the current epoch.
    pub curr_epoch: Option<EpochId>,
}

/// Sui environment to decide what network to use.
#[derive(Default, Debug, Serialize, Deserialize)]
pub enum SuiEnv {
    #[default]
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
}

impl SuiEnv {
    /// Returns the url string and ZkLoginEnv for the given Sui environment.
    fn get_params(&self) -> (&str, ZkLoginEnv) {
        match self {
            SuiEnv::Mainnet => ("https://fullnode.mainnet.sui.io:443", ZkLoginEnv::Prod),
            SuiEnv::Testnet => ("https://fullnode.testnet.sui.io:443", ZkLoginEnv::Prod),
            SuiEnv::Devnet => ("https://fullnode.devnet.sui.io:443", ZkLoginEnv::Test),
            SuiEnv::Localnet => ("http://127.0.0.1:9000", ZkLoginEnv::Test),
        }
    }
}