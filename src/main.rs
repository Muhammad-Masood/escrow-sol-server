// use solana_program::pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
    system_program,
    commitment_config::CommitmentConfig,
    program_pack::Pack,
    pubkey::Pubkey,
};
use anchor_lang::InstructionData;
use serde::{Deserialize, Serialize};
use warp::Filter;
use solana_sdk::instruction::AccountMeta;
use std::str::FromStr;
use escrow_project::instruction::{StartSubscription, ExtendSubscription, Prove, EndSubscriptionByBuyer, EndSubscriptionByServer};
use warp::reject::Reject;
use solana_client::client_error::ClientError;

#[derive(Debug)]
struct CustomClientError(ClientError);

impl Reject for CustomClientError {}

const PROGRAM_ID: &str = "HPFKvGvdtChrFrfqzAYzbNZJ3sRKw9HDHMKWgtZg1oNs";
// const RPC_URL: &str = "https://api.localnet.solana.com";
const RPC_URL: &str = "http://127.0.0.1:8899";

#[derive(Serialize, Deserialize)]
struct StartSubscriptionRequest {
    query_size: u64,
    number_of_blocks: u64,
    x: u64,
    g: u64,
    v: u64,
    u: u64,
    buyer_private_key: String,
}

#[derive(Serialize, Deserialize)]
struct ExtendSubscriptionRequest {
    buyer_private_key: String,
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct ProveRequest {
    seller_private_key: String,
    escrow_pubkey: String,
    buyer_pubkey: String,
    sigma: u64,
    mu: u64,
}

#[derive(Serialize, Deserialize)]
struct EndSubscriptionByBuyerRequest {
    buyer_private_key: String,
    seller_pubkey: String,
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct StartSubscriptionResponse {
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct ExtendSubscriptionResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct ProveResponse {
    message: String,
}

#[tokio::main]
async fn main() {
    let start_subscription = warp::post()
        .and(warp::path("start_subscription"))
        .and(warp::body::json())
        .and_then(start_subscription_handler);
    
    let extend_subscription = warp::post()
        .and(warp::path("extend_subscription"))
        .and(warp::body::json())
        .and_then(extend_subscription_handler);
    
    let prove = warp::post()
        .and(warp::path("prove"))
        .and(warp::body::json())
        .and_then(prove_handler);

    let end_sub_by_buyer = warp::post()
        .and(warp::path("end_subscription_by_buyer"))
        .and(warp::body::json())
        .and_then(end_subscription_by_buyer_handler);

    let end_sub_by_server = warp::post()
        .and(warp::path("end_subscription_by_server"))
        .and(warp::body::json())
        .and_then(end_subscription_by_server_handler);

    let routes = start_subscription.or(extend_subscription).or(prove).or(end_sub_by_buyer).or(end_sub_by_server);
    println!("Server running at http://127.0.0.1:3030/");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn start_subscription_handler(request: StartSubscriptionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let buyer_keypair = Keypair::from_base58_string(&request.buyer_private_key);
    let buyer_pubkey = buyer_keypair.pubkey();

    let (escrow_pda, bump) = Pubkey::find_program_address(&[b"escrow", buyer_pubkey.as_ref()], &program_id);

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pda, false),
            AccountMeta::new(buyer_pubkey, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: StartSubscription {
            query_size: request.query_size,
            number_of_blocks: request.number_of_blocks,
            x: request.x,
            g: request.g,
            v: request.v,
            u: request.u,
        }.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&buyer_pubkey),
        &[&buyer_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&StartSubscriptionResponse { escrow_pubkey: escrow_pda.to_string() })),
        // Ok(sig) => Ok(warp::reply::json(&sig)),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
        // Err(err) => Err(warp::reject::custom(err)),
    }
}

// Called by the Buyer
async fn extend_subscription_handler(request: ExtendSubscriptionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let buyer_keypair = Keypair::from_base58_string(&request.buyer_private_key);
    let buyer_pubkey = buyer_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(buyer_pubkey, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: ExtendSubscription {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&buyer_pubkey),
        &[&buyer_keypair],
        blockhash,
    );
    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Subscription extended successfully".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

// Called by the Seller
async fn prove_handler(request: ProveRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let seller_keypair = Keypair::from_base58_string(&request.seller_private_key);
    let seller_pubkey = seller_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();
    let buyer_pubkey = Pubkey::from_str(&request.buyer_pubkey).unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(seller_pubkey, true),
            AccountMeta::new(buyer_pubkey, false),
            // AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: Prove {
            sigma: request.sigma,
            mu: request.mu,
        }
        .data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&seller_pubkey),
        &[&seller_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ProveResponse { message: "Proof submitted successfully".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

async fn end_subscription_by_buyer_handler(request: EndSubscriptionByBuyerRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let buyer_keypair = Keypair::from_base58_string(&request.buyer_private_key);
    let buyer_pubkey = buyer_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();
    let seller_pubkey = Pubkey::from_str(&request.seller_pubkey).unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(buyer_pubkey, true),
            AccountMeta::new(seller_pubkey, false),
            // AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: EndSubscriptionByBuyer {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&buyer_pubkey),
        &[&buyer_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Subscription ended successfully by buyer".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

async fn end_subscription_by_server_handler(request: ExtendSubscriptionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let buyer_keypair = Keypair::from_base58_string(&request.buyer_private_key);
    let buyer_pubkey = buyer_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(buyer_pubkey, true),
            // AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: EndSubscriptionByServer {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&buyer_pubkey),
        &[&buyer_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Subscription ended successfully by server".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}