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
use anchor_lang::{AccountDeserialize, InstructionData};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use warp::Filter;
use solana_sdk::instruction::AccountMeta;
use std::str::FromStr;
use escrow_project::instruction::{AddFundsToSubscription, StartSubscription, ProveSubscription, EndSubscriptionByBuyer, EndSubscriptionBySeller, RequestFund, GenerateQueries};
use warp::reject::Reject;
use std::num::ParseIntError;
use std::ops::Mul;
use solana_client::client_error::ClientError;
use std::time::{SystemTime, UNIX_EPOCH};
use escrow_project::Escrow;
// use solana_sdk::sysvar::slot_hashes;
use serde::de::{Error as DeError};
use bls12_381::{pairing, G1Affine, G2Affine, G1Projective, Scalar, G2Projective};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct HexArray<const N: usize>([u8; N]);

impl<const N: usize> Serialize for HexArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexArray<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(DeError::custom)?;
        if bytes.len() != N {
            return Err(DeError::custom(format!(
                "Invalid length: expected {} bytes, got {} bytes",
                N,
                bytes.len()
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(HexArray(array))
    }
}

mod hex_array_96 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<96>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

mod hex_array_48 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<48>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<32>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

#[derive(Debug)]
struct CustomClientError(ClientError);

impl Reject for CustomClientError {}

#[derive(Debug)]
pub struct CClientError {
    message: String,
}

impl From<ParseIntError> for CClientError {
    fn from(err: ParseIntError) -> Self {
        CClientError {
            message: format!("Invalid number format: {}", err),
        }
    }
}
impl Reject for CClientError {}

const PROGRAM_ID: &str = "5LthHd6oNK3QkTwC59pnn1tPFK7JJUgNjNnEptxxXSei";
// const RPC_URL: &str = "https://api.localnet.solana.com";
const RPC_URL: &str = "http://127.0.0.1:8899";

#[derive(Serialize, Deserialize, Debug)]
struct StartSubscriptionRequest {
    query_size: u64,
    number_of_blocks: u64,
    #[serde(with = "hex_array_48")]
    u: [u8; 48],
    #[serde(with = "hex_array_96")]
    g: [u8; 96],
    #[serde(with = "hex_array_96")]
    v: [u8; 96],
    validate_every: i64,
    buyer_private_key: String,
    seller_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct AddFundsToSubscriptionRequest {
    buyer_private_key: String,
    escrow_pubkey: String,
    amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProveRequest {
    seller_private_key: String,
    escrow_pubkey: String,
    #[serde(with = "hex_array_48")]
    sigma: [u8; 48],
    #[serde(with = "hex_array_32")]
    mu: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct EndSubscriptionByBuyerRequest {
    buyer_private_key: String,
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct EndSubscriptionBySellerRequest {
    seller_private_key: String,
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct RequestFundsRequest2 {
    subscription_id: u64,
    buyer_pubkey: String,
    user_private_key: String,  // Can be buyer or seller
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct RequestFundsRequest {
    // subscription_id: u64,
    // buyer_pubkey: String,   // remains same in cases of request by buyer or seller
    // seller_pubkey: String,  // requried if buyer is doing request in order to get the escrow_pda
    user_private_key: String,   // can be buyer or seller (Requester), used as a signer
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateQueriesRequest {
    escrow_pubkey: String,
    user_private_key: String,
}

#[derive(Serialize, Deserialize)]
struct GetQueriesByEscrowPubKeyRequest {
    escrow_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct StartSubscriptionResponse {
    escrow_pubkey: String,
    subscription_id: u64,
}

#[derive(Serialize, Deserialize)]
struct ExtendSubscriptionResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct ProveResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct GetQueriesByEscrowPubkeyResponse {
    queries: Vec<(u128, String)>, //(block index, v_i)
}

#[tokio::main]
async fn main() {
    let start_subscription = warp::post()
        .and(warp::path("start_subscription"))
        .and(warp::body::json())
        .and_then(start_subscription_handler);
    
    let add_funds_to_subscription = warp::post()
        .and(warp::path("add_funds_to_subscription"))
        .and(warp::body::json())
        .and_then(add_funds_to_subscription_handler);
    
    let prove = warp::post()
        .and(warp::path("prove"))
        .and(warp::body::json())
        .and_then(prove_handler);

    let end_sub_by_buyer = warp::post()
        .and(warp::path("end_subscription_by_buyer"))
        .and(warp::body::json())
        .and_then(end_subscription_by_buyer_handler);

    let end_sub_by_seller = warp::post()
        .and(warp::path("end_subscription_by_seller"))
        .and(warp::body::json())
        .and_then(end_subscription_by_seller_handler);
    
    let generate_queries = warp::post()
        .and(warp::path("generate_queries"))
        .and(warp::body::json())
        .and_then(generate_queries_handler);

    let get_queries_by_escrow_pubkey = warp::post()
        .and(warp::path("get_queries_by_escrow_pubkey"))
        .and(warp::body::json())
        .and_then(get_queries_by_escrow_pubkey_handler);

    let request_funds = warp::post()
        .and(warp::path("request_funds"))
        .and(warp::body::json())
        .and_then(request_funds_handler);

    let routes = start_subscription
        .or(add_funds_to_subscription)
        .or(prove).or(end_sub_by_buyer)
        .or(end_sub_by_seller)
        .or(generate_queries)
        .or(get_queries_by_escrow_pubkey)
        .or(request_funds);

    println!("Server running at http://127.0.0.1:3030/");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn start_subscription_handler(request: StartSubscriptionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let buyer_keypair = Keypair::from_base58_string(&request.buyer_private_key);
    let buyer_pubkey = buyer_keypair.pubkey();
    let seller_pubkey = Pubkey::from_str(&request.seller_pubkey).unwrap();
    let subscription_id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // let (escrow_pda, bump) = Pubkey::find_program_address(&[b"escrow", buyer_pubkey.as_ref()], &program_id);
    
    let (escrow_pda, bump) = Pubkey::find_program_address(&[
        b"escrow",
        buyer_pubkey.as_ref(),
        seller_pubkey.as_ref(),
        &subscription_id.to_le_bytes()
    ], &program_id);

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pda, false),
            AccountMeta::new(buyer_pubkey, true),
            AccountMeta::new(seller_pubkey, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: StartSubscription {
            subscription_id,
            query_size: request.query_size,
            number_of_blocks: request.number_of_blocks,
            g: request.g,
            v: request.v,
            u: request.u,
            validate_every: request.validate_every,
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
        Ok(_) => Ok(warp::reply::json(&StartSubscriptionResponse { subscription_id: subscription_id, escrow_pubkey: escrow_pda.to_string() })),
        // Ok(sig) => Ok(warp::reply::json(&sig)),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
        // Err(err) => Err(warp::reject::custom(err)),
    }
}

async fn add_funds_to_subscription_handler(request: AddFundsToSubscriptionRequest) -> Result<impl warp::Reply, warp::Rejection> {
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
        data: AddFundsToSubscription {
            amount: request.amount,
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
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Subscription extended successfully".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

fn convert_u128_to_32_bytes(i: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];  // Create a 32-byte array, initially all zeros

    // Convert the u128 into bytes (16 bytes) and place it in the last 16 bytes of the array
    bytes[16..32].copy_from_slice(&i.to_be_bytes());  // Using big-endian format

    bytes
}

fn perform_hash_to_curve(i: u128) -> G1Affine {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    // Convert u128 to 32-byte array
    let msg = convert_u128_to_32_bytes(i);

    // Perform hash-to-curve
    let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&msg, dst);

    // Convert from G1Projective to G1Affine
    G1Affine::from(&g)
}

fn hex_to_bytes_le(hex_str: &str) -> [u8; 32] {
    // Remove "0x" prefix if present
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Decode hex string to Vec<u8>
    let mut bytes = hex::decode(hex_str).expect("Invalid hex string");

    // Reverse byte order for little-endian representation
    bytes.reverse();

    // Convert Vec<u8> to [u8; 32]
    bytes.try_into().expect("Hex string should be 32 bytes long")
}

fn big_endian_hex_str_to_scalar(hex_str: &str) -> Scalar {
    let uu = hex_to_bytes_le(&hex_str);

    // Convert bytes to Scalar
    Scalar::from_bytes(&uu).unwrap()
}

fn reverse_endianness(input: [u8; 32]) -> [u8; 32] {
    let mut reversed = input;
    reversed.reverse();
    reversed
}

fn compute_h_i_multiply_vi(queries: Vec<(u128, [u8; 32])>) -> G1Projective {
    let mut all_h_i_multiply_vi = G1Projective::identity();

    for (i, v_i_hex) in queries {
        let h_i = perform_hash_to_curve(i); //  H(i)
        let v_i = Scalar::from_bytes(&reverse_endianness(v_i_hex)).unwrap();    //  v_i
        let h_i_multiply_v_i = h_i.mul(v_i);    //  H(i)^(v_i)

        all_h_i_multiply_vi = all_h_i_multiply_vi.add(&h_i_multiply_v_i);
    }

    all_h_i_multiply_vi //  Π(H(i)^(v_i))
}

// Called by the Seller
async fn prove_handler(request: ProveRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let seller_keypair = Keypair::from_base58_string(&request.seller_private_key);
    let seller_pubkey = seller_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();
    
    let account_data = rpc_client.get_account_data(&escrow_pubkey).unwrap();
    let escrow_account = Escrow::try_deserialize(&mut &account_data[..]).unwrap();

    let g_norm = G2Affine::from_compressed(&escrow_account.g).unwrap();
    let v_norm = G2Affine::from_compressed(&escrow_account.v).unwrap();
    let u = G1Affine::from_compressed(&escrow_account.u).unwrap();

    let mu_in_little_endian: [u8; 32] = request.mu;
    let mu_scalar = Scalar::from_bytes(&mu_in_little_endian).unwrap();

    let sigma = G1Affine::from_compressed(&request.sigma).unwrap();

    let queries = escrow_account.queries;

    let all_h_i_multiply_vi = compute_h_i_multiply_vi(queries);

    let u_multiply_mu = u.mul(mu_scalar);

    let multiplication_sum = all_h_i_multiply_vi.add(&u_multiply_mu);
    let multiplication_sum_affine = G1Affine::from(multiplication_sum);

    let right_pairing = pairing(&multiplication_sum_affine, &v_norm);

    let left_pairing = pairing(&sigma, &g_norm);

    let is_verified = left_pairing.eq(&right_pairing);
    println!("{}", is_verified);


    Ok(warp::reply::json(&ProveResponse { message: "Proof submitted successfully".to_string() }))

    // let instruction = Instruction {
    //     program_id,
    //     accounts: vec![
    //         AccountMeta::new(escrow_pubkey, false),
    //         AccountMeta::new(seller_pubkey, true),
    //         // AccountMeta::new_readonly(system_program::ID, false),
    //     ],
    //     data: ProveSubscription {
    //         sigma: request.sigma,
    //         mu: mu,
    //     }
    //     .data(),
    // };
    //
    // let blockhash = rpc_client.get_latest_blockhash().unwrap();
    // let tx = Transaction::new_signed_with_payer(
    //     &[instruction],
    //     Some(&seller_pubkey),
    //     &[&seller_keypair],
    //     blockhash,
    // );
    //
    // match rpc_client.send_and_confirm_transaction(&tx) {
    //     Ok(_) => Ok(warp::reply::json(&ProveResponse { message: "Proof submitted successfully".to_string() })),
    //     Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    // }
}

async fn end_subscription_by_buyer_handler(request: EndSubscriptionByBuyerRequest) -> Result<impl warp::Reply, warp::Rejection> {
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

async fn end_subscription_by_seller_handler(request: EndSubscriptionBySellerRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let seller_keypair = Keypair::from_base58_string(&request.seller_private_key);
    let seller_pubkey = seller_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(seller_pubkey, true),
            // AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: EndSubscriptionBySeller {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&seller_pubkey),
        &[&seller_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Subscription ended successfully by seller".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

async fn request_funds_handler(request: RequestFundsRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let user_keypair = Keypair::from_base58_string(&request.user_private_key);
    let user_pubkey = user_keypair.pubkey();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();

    println!("Client-side PDA: {}", escrow_pubkey);

    let instruction = Instruction {
        program_id,
        accounts: vec![
            // AccountMeta::new(escrow_pda, false),
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new(user_pubkey, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: RequestFund {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&user_pubkey),
        &[&user_keypair],
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Funds requested successfully".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

async fn generate_queries_handler(request: GenerateQueriesRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();
    let user_keypair = Keypair::from_base58_string(&request.user_private_key);
    let user_pubkey = user_keypair.pubkey();

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(escrow_pubkey, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: GenerateQueries {}.data(),
    };

    let blockhash = rpc_client.get_latest_blockhash().unwrap();
    let signers = [&user_keypair];
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        // None,  // No need for signer as it's an update call
        // &[],
        Some(&user_pubkey),
        &signers,
        blockhash,
    );

    match rpc_client.send_and_confirm_transaction(&tx) {
        Ok(_) => Ok(warp::reply::json(&ExtendSubscriptionResponse { message: "Queries generated successfully".to_string() })),
        Err(err) => Err(warp::reject::custom(CustomClientError(err)))
    }
}

async fn get_queries_by_escrow_pubkey_handler(
    request: GetQueriesByEscrowPubKeyRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let escrow_pubkey = Pubkey::from_str(&request.escrow_pubkey).unwrap();

    let account_data = rpc_client.get_account_data(&escrow_pubkey).unwrap();
    let escrow_account = Escrow::try_deserialize(&mut &account_data[..]).unwrap();

    let queries: Vec<(u128, [u8; 32])> = escrow_account.queries;

    let transformed_queries: Vec<(u128, String)> = queries
        .into_iter()
        .map(|(num, bytes)| {
            let extracted_num = hex::encode(bytes);
            (num, extracted_num)
        })
        .collect();

    Ok(warp::reply::json(&GetQueriesByEscrowPubkeyResponse { queries: transformed_queries }))
}