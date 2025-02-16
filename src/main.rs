use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use solana_client::rpc_client::RpcClient;
use anchor_lang::prelude::*;
use tokio::net::TcpListener;
use std::str::FromStr;

const PROGRAM_ID: &str = "EYELQu2CtqBa8S4Z3e8DFBExsUEtb4aGMzqHMJWrgekr";
const RPC_URL: &str = "https://api.devnet.solana.com";

#[derive(Deserialize)]
struct StartSubscriptionRequest {
    buyer_private_key: String,
    seller_pubkey: String,
    subscription_id: String,
    validation_threshold: u64,
}

#[derive(Serialize)]
struct ApiResponse {
    message: String,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
struct StartSubscriptionData {
    subscription_id: String,
    validation_threshold: u64,
}

// Start Subscription API
async fn start_subscription(Json(payload): Json<StartSubscriptionRequest>) -> Json<ApiResponse> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    
    // Convert keys
    let buyer_keypair = Keypair::from_base58_string(&payload.buyer_private_key);
    let seller_pubkey = Pubkey::from_str(&payload.seller_pubkey).unwrap();
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();

    // Derive escrow account PDA
    let (escrow_account, _bump) = Pubkey::find_program_address(
        &[
            b"escrow",
            buyer_keypair.pubkey().as_ref(),
            seller_pubkey.as_ref(),
            payload.subscription_id.as_bytes(),
        ],
        &program_id,
    );

    // Create transaction to call `start_subscription`
    let instruction_data = StartSubscriptionData {
        subscription_id: payload.subscription_id.clone(),
        validation_threshold: payload.validation_threshold,
    };

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_account, false),
            AccountMeta::new_readonly(buyer_keypair.pubkey(), true),
            AccountMeta::new_readonly(seller_pubkey, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: instruction_data.try_to_vec().unwrap(), // Serialize data
    };

    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();

    let mut transaction = Transaction::new_with_payer(&[ix], Some(&buyer_keypair.pubkey()));
    transaction.sign(&[&buyer_keypair], recent_blockhash);

    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(sig) => Json(ApiResponse {
            message: format!("Transaction sent! Signature: {}", sig),
        }),
        Err(err) => Json(ApiResponse {
            message: format!("Error: {:?}", err),
        }),
    }
}

async fn hello_world() -> Json<ApiResponse> {
    Json(ApiResponse {
        message: "Hello, world!".to_string(),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/start_subscription", post(start_subscription))
        .route("/hello", get(hello_world));

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
