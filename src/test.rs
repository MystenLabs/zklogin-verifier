// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{verify, AppState, VerifyError, VerifyRequest};
use axum::{extract::State, Json};
use fastcrypto_zkp::bn254::zk_login::{JwkId, OIDCProvider, JWK};
use shared_crypto::intent::IntentScope;
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn test_verify() {
    let mut map = HashMap::new();
    map.insert(
        OIDCProvider::Twitch,
        vec!["rs1bh065i9ya4ydvifixl4kss0uhpt".to_string()],
    );

    let state = Arc::new(AppState {
        jwks: Default::default(),
    });
    let state_clone = state.clone();
    {
        let mut oauth_provider_jwk = state_clone.jwks.write();
        oauth_provider_jwk.insert(JwkId::new("https://id.twitch.tv/oauth2".to_string(), "1".to_string()), JWK {
            alg: "RS256".to_string(),
            e: "AQAB".to_string(),
            kty: "RSA".to_string(),
            n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
        });
    }
    let sig = "BQNNMTczMTgwODkxMjU5NTI0MjE3MzYzNDIyNjM3MTc5MzI3MTk0Mzc3MTc4NDQyODI0MTAxODc5NTc5ODQ3NTE5Mzk5NDI4OTgyNTEyNTBNMTEzNzM5NjY2NDU0NjkxMjI1ODIwNzQwODIyOTU5ODUzODgyNTg4NDA2ODE2MTgyNjg1OTM5NzY2OTczMjU4OTIyODA5MTU2ODEyMDcBMQMCTDU5Mzk4NzExNDczNDg4MzQ5OTczNjE3MjAxMjIyMzg5ODAxNzcxNTIzMDMyNzQzMTEwNDcyNDk5MDU5NDIzODQ5MTU3Njg2OTA4OTVMNDUzMzU2ODI3MTEzNDc4NTI3ODczMTIzNDU3MDM2MTQ4MjY1MTk5Njc0MDc5MTg4ODI4NTg2NDk2Njg4NDAzMjcxNzA0OTgxMTcwOAJNMTA1NjQzODcyODUwNzE1NTU0Njk3NTM5OTA2NjE0MTA4NDAxMTg2MzU5MjU0NjY1OTcwMzcwMTgwNTg3NzAwNDEzNDc1MTg0NjEzNjhNMTI1OTczMjM1NDcyNzc1NzkxNDQ2OTg0OTYzNzIyNDI2MTUzNjgwODU4MDEzMTMzNDMxNTU3MzU1MTEzMzAwMDM4ODQ3Njc5NTc4NTQCATEBMANNMTU3OTE1ODk0NzI1NTY4MjYyNjMyMzE2NDQ3Mjg4NzMzMzc2MjkwMTUyNjk5ODQ2OTk0MDQwNzM2MjM2MDMzNTI1Mzc2Nzg4MTMxNzFMNDU0Nzg2NjQ5OTI0ODg4MTQ0OTY3NjE2MTE1ODAyNDc0ODA2MDQ4NTM3MzI1MDAyOTQyMzkwNDExMzAxNzQyMjUzOTAzNzE2MjUyNwExMXdpYVhOeklqb2lhSFIwY0hNNkx5OXBaQzUwZDJsMFkyZ3VkSFl2YjJGMWRHZ3lJaXcCMmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0ltdHBaQ0k2SWpFaWZRTTIwNzk0Nzg4NTU5NjIwNjY5NTk2MjA2NDU3MDIyOTY2MTc2OTg2Njg4NzI3ODc2MTI4MjIzNjI4MTEzOTE2MzgwOTI3NTAyNzM3OTExCgAAAAAAAABhAG6Bf8BLuaIEgvF8Lx2jVoRWKKRIlaLlEJxgvqwq5nDX+rvzJxYAUFd7KeQBd9upNx+CHpmINkfgj26jcHbbqAy5xu4WMO8+cRFEpkjbBruyKE9ydM++5T/87lA8waSSAA==";
    let bytes = "AAABACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgEBAQABAAAcpgUkGBwS5nPO79YXkjMyvaRjGS57hqxzfyd2yGtejwGbB4FfBEl+LgXSLKw6oGFBCyCGjMYZFUxCocYb6ZAnFwEAAAAAAAAAIJZw7UpW1XHubORIOaY8d2+WyBNwoJ+FEAxlsa7h7JHrHKYFJBgcEuZzzu/WF5IzMr2kYxkue4asc38ndshrXo8BAAAAAAAAABAnAAAAAAAAAA==";

    let res = verify(
        State(state.clone()),
        Json(VerifyRequest {
            signature: sig.to_string(),
            bytes: bytes.to_string(),
            intent_scope: IntentScope::TransactionData,
            author: None,
            network: Some(crate::SuiEnv::Devnet),
            curr_epoch: Some(1),
        }),
    )
    .await;
    assert!(res.is_ok());
    assert!(res.unwrap().0.is_verified);

    // Wrong network fails to verify.
    let res = verify(
        State(state.clone()),
        Json(VerifyRequest {
            signature: sig.to_string(),
            bytes: bytes.to_string(),
            intent_scope: IntentScope::TransactionData,
            author: None,
            network: Some(crate::SuiEnv::Mainnet),
            curr_epoch: Some(1),
        }),
    )
    .await;
    assert!(matches!(res.unwrap_err(), VerifyError::GenericError(..)));

    // Wrong epoch fails to verify.
    let res = verify(
        State(state.clone()),
        Json(VerifyRequest {
            signature: sig.to_string(),
            bytes: bytes.to_string(),
            intent_scope: IntentScope::TransactionData,
            author: None,
            network: Some(crate::SuiEnv::Devnet),
            curr_epoch: Some(11),
        }),
    )
    .await;
    assert!(matches!(res.unwrap_err(), VerifyError::GenericError(..)));

    // Wrong intent scope fails to verify.
    let res = verify(
        State(state.clone()),
        Json(VerifyRequest {
            signature: sig.to_string(),
            bytes: bytes.to_string(),
            intent_scope: IntentScope::PersonalMessage,
            author: None,
            network: Some(crate::SuiEnv::Devnet),
            curr_epoch: Some(1),
        }),
    )
    .await;
    assert_eq!(res.unwrap_err(), VerifyError::ParsingError);

    // Bad ephemeral signature fails to verify
    let res = verify(
        State(state.clone()),
        Json(VerifyRequest {
            signature: "badsig".to_string(),
            bytes: bytes.to_string(),
            intent_scope: IntentScope::PersonalMessage,
            author: None,
            network: Some(crate::SuiEnv::Devnet),
            curr_epoch: Some(1),
        }),
    )
    .await;
    assert_eq!(res.unwrap_err(), VerifyError::ParsingError);
}
