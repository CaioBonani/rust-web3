// #![allow(unused)]


use solana_sdk::message::Message;
use solana_sdk::{
    signer::keypair::Keypair,
    transaction::Transaction,
    pubkey::Pubkey,
};

use solana_client::rpc_client::RpcClient;
use std::net::SocketAddr;
use std::str::FromStr;
// use std::str::FromStr;
use bs58::decode;
use serde_json::Value;
use hyper::rt;
use hyper::{Body, Request, Response, service::service_fn, Server};

fn make_airdrop(public_key: &str, amount: u64, client: &RpcClient, signer: &Keypair) {
    let to = Pubkey::from_str(public_key).unwrap();

    let instruction = 

    let message = Message::new(&[signer.pubkey()], &[to], client.get_latest_blockhash().unwrap());

    let transaction = Transaction::new(
        &[signer], 
        vec![(to, amount)], 
        client.get_latest_blockhash());

    let result = client.send_transaction(transaction);
    match result {
        Ok(transaction_response) => println!("Transaction successful: {:?}", transaction_response),
        Err(error) => println!("Transaction error: {:?}", error),
    }
}

async fn api_handler(req: Request<Body>) -> Response<Body> {
    let client = RpcClient::new("https://testnet.solana.com");

    let private_key: String;
    let public_key: String;
    let amount: u64;

    let body = req.into_body();
    let body_bytes = hyper::body::to_bytes(body).await.unwrap();
    let body_string = String::from_utf8(body_bytes.to_vec()).unwrap();
    let body_json: Value = serde_json::from_str(&body_string).unwrap();

    match body_json["private_key"].as_str() {
        Some(key) => private_key = key.to_string(),
        None => return Response::new(Body::from("No private key")),
    }

    match body_json["public_key"].as_str() {
        Some(key) => public_key = key.to_string(),
        None => return Response::new(Body::from("No public key")),
    }

    match body_json["amount"].as_u64() {
        Some(key) => amount = key,
        None => return Response::new(Body::from("No amount")),
    }

    let private_key_str = private_key.as_str();
    let public_key_str = public_key.as_str();

    let signer = Keypair::from_base58_string(&private_key_str);

    make_airdrop(&public_key_str, amount, &client, &signer);

    Response::new(Body::from("Airdrop successful"))
}

fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let new_svc = || {
        service_fn(api_handler)
    };

    let server = Server::bind(&addr)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    rt::run(server);
}