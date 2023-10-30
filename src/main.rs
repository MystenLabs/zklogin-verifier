// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::{
    routing::{get, post},
    Router,
};
use fastcrypto_zkp::bn254::zk_login::{fetch_jwks, OIDCProvider};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, warn};
use zklogin_verifier::{verify, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::FmtSubscriber::builder()
        .try_init()
        .expect("setting default subscriber failed");

    let state = Arc::new(AppState {
        jwks: Default::default(),
    });

    let state_clone = state.clone();

    tokio::task::spawn(async move {
        info!("Starting JWK updater task");
        loop {
            let client = reqwest::Client::new();
            for p in [
                OIDCProvider::Facebook,
                OIDCProvider::Google,
                OIDCProvider::Twitch,
                OIDCProvider::Kakao,
                OIDCProvider::Apple,
                OIDCProvider::Slack,
            ] {
                match fetch_jwks(&p, &client).await {
                    Err(e) => {
                        warn!("Error when fetching JWK with provider {:?} {:?}", p, e);
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    Ok(keys) => {
                        for (jwk_id, jwk) in keys {
                            let mut oauth_provider_jwk = state_clone.jwks.write();
                            if oauth_provider_jwk.contains_key(&jwk_id) {
                                continue;
                            }
                            info!("{:?} JWK updated: {:?}", &jwk_id, jwk);
                            // todo(joyqvq): prune old jwks.
                            oauth_provider_jwk.insert(jwk_id, jwk.clone());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    let app = Router::new()
        .route("/", get(ping))
        .route("/verify", post(verify))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn ping() -> &'static str {
    "Pong!"
}
