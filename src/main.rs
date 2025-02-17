use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use anchor_lang::InstructionData;
use borsh::{BorshSerialize, BorshDeserialize};
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

const PROGRAM_ID: &str = "9hzPKhXhtHNcWcHRQChc1otQfJHgCpsJKj2ofjC6YYmw";
// const PROGRAM_ID: &str = "CMUGDifD2QbDVs5dvMWhm1Y4a4v8Sh9frE37XX9BGnS";
// const PROGRAM_ID: &str = "ACTncW7Szs5JW6TBo4xeSAzaYFqNjGnCeXLUsChbECxv";
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

#[derive(Deserialize)]
struct MakePaymentRequest {
    buyer_private_key: String,
    seller_pubkey: String,
    subscription_id: String,
    amount: u64,
}

#[derive(Deserialize)]
struct CancelSubscriptionRequest {
    buyer_private_key: String,
    seller_pubkey: String,
    subscription_id: String,
}

#[derive(Deserialize)]
struct WithdrawFundsRequest {
    seller_private_key: String,
    buyer_pubkey: String,
    subscription_id: String,
    validation_data: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct MakePaymentData {
    amount: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct CancelSubscriptionData {}  // No fields needed

#[derive(BorshSerialize, BorshDeserialize)]
struct WithdrawFundsData {
    validation_data: u64,
}


async fn home() -> Json<ApiResponse> {
    Json(ApiResponse {
        message: "Welcome to the Solana Escrow!".to_string(),
    })
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
    println!("{}",PROGRAM_ID);
    // Create transaction to call `start_subscription`
    let instruction_data = StartSubscriptionData {
        subscription_id: payload.subscription_id.clone(),
        validation_threshold: payload.validation_threshold,
    };

    let ix = Instruction {
        program_id,
        accounts: vec![
        AccountMeta::new(escrow_account, false),
        AccountMeta::new(buyer_keypair.pubkey(), true), 
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

async fn make_payment(Json(payload): Json<MakePaymentRequest>) -> Json<ApiResponse> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());

    let buyer_keypair = Keypair::from_base58_string(&payload.buyer_private_key);
    let seller_pubkey = Pubkey::from_str(&payload.seller_pubkey).unwrap();
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();

    let (escrow_account, _bump) = Pubkey::find_program_address(
        &[
            b"escrow",
            buyer_keypair.pubkey().as_ref(),
            seller_pubkey.as_ref(),
            payload.subscription_id.as_bytes(),
        ],
        &program_id,
    );
    let instruction_data = MakePaymentData {
        amount: payload.amount,
    };
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_account, false),
            AccountMeta::new_readonly(buyer_keypair.pubkey(), true),
            AccountMeta::new_readonly(seller_pubkey, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        // data: anchor_lang::InstructionData::data(&(payload.amount)),
        data: instruction_data.try_to_vec().unwrap(),
    };

    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();
    let mut transaction = Transaction::new_with_payer(&[ix], Some(&buyer_keypair.pubkey()));
    transaction.sign(&[&buyer_keypair], recent_blockhash);

    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(sig) => Json(ApiResponse {
            message: format!("Payment successful! Signature: {}", sig),
        }),
        Err(err) => Json(ApiResponse {
            message: format!("Error: {:?}", err),
        }),
    }
}

async fn cancel_subscription(Json(payload): Json<CancelSubscriptionRequest>) -> Json<ApiResponse> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());

    let buyer_keypair = Keypair::from_base58_string(&payload.buyer_private_key);
    let seller_pubkey = Pubkey::from_str(&payload.seller_pubkey).unwrap();
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();

    let (escrow_account, _bump) = Pubkey::find_program_address(
        &[
            b"escrow",
            buyer_keypair.pubkey().as_ref(),
            seller_pubkey.as_ref(),
            payload.subscription_id.as_bytes(),
        ],
        &program_id,
    );
    let instruction_data = CancelSubscriptionData {};
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_account, false),
            AccountMeta::new_readonly(buyer_keypair.pubkey(), true),
            AccountMeta::new_readonly(seller_pubkey, false),
        ],
        // data: anchor_lang::InstructionData::data(&()), // No extra parameters needed
        data: instruction_data.try_to_vec().unwrap(),
    };

    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();
    let mut transaction = Transaction::new_with_payer(&[ix], Some(&buyer_keypair.pubkey()));
    transaction.sign(&[&buyer_keypair], recent_blockhash);

    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(sig) => Json(ApiResponse {
            message: format!("Subscription canceled! Signature: {}", sig),
        }),
        Err(err) => Json(ApiResponse {
            message: format!("Error: {:?}", err),
        }),
    }
}

async fn withdraw_funds(Json(payload): Json<WithdrawFundsRequest>) -> Json<ApiResponse> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());

    let seller_keypair = Keypair::from_base58_string(&payload.seller_private_key);
    let buyer_pubkey = Pubkey::from_str(&payload.buyer_pubkey).unwrap();
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();

    let (escrow_account, _bump) = Pubkey::find_program_address(
        &[
            b"escrow",
            buyer_pubkey.as_ref(),
            seller_keypair.pubkey().as_ref(),
            payload.subscription_id.as_bytes(),
        ],
        &program_id,
    );
    let instruction_data = WithdrawFundsData {
        validation_data: payload.validation_data,
    };
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_account, false),
            AccountMeta::new_readonly(buyer_pubkey, false),
            AccountMeta::new_readonly(seller_keypair.pubkey(), true),
        ],
        data: instruction_data.try_to_vec().unwrap(),
    };

    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();
    let mut transaction = Transaction::new_with_payer(&[ix], Some(&seller_keypair.pubkey()));
    transaction.sign(&[&seller_keypair], recent_blockhash);

    match rpc_client.send_and_confirm_transaction(&transaction) {
        Ok(sig) => Json(ApiResponse {
            message: format!("Funds withdrawn! Signature: {}", sig),
        }),
        Err(err) => Json(ApiResponse {
            message: format!("Error: {:?}", err),
        }),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
    .route("/hello", get(home))
    .route("/start_subscription", post(start_subscription))
    .route("/make_payment", post(make_payment))
    .route("/cancel_subscription", post(cancel_subscription))
    .route("/withdraw_funds", post(withdraw_funds));

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
