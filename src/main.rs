// #![allow(unused)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::convert::Infallible;

use solana_sdk::message::Message;
use solana_sdk::{
    signer::keypair::Keypair,
    transaction::Transaction,
    pubkey::Pubkey,
    instruction::Instruction,
};
use solana_client::rpc_client::RpcClient;
use spl_token::ID;

use serde_json::Value;

use hyper::rt;
use hyper::{Body, Request, Response, service::service_fn, Server, service::make_service_fn};

fn make_airdrop(public_key: &str, amount: u64, client: &RpcClient, signer: &Keypair) {
    let to = Pubkey::from_str(public_key).unwrap();

    let from = Pubkey::from_str(&signer.to_base58_string()).unwrap();


    let instruction = spl_token::instruction::transfer(
        &ID,
        &Pubkey::from_str(&signer.to_base58_string()).unwrap(),
        &to,
        &Pubkey::from_str(&signer.to_base58_string()).unwrap(),
        &[],
        amount,
    ).unwrap();

    let message = Message::new(&[instruction], Some(&from));

    let transaction = Transaction::new(&[signer], message, client.get_latest_blockhash().unwrap());

    let result = client.send_transaction(&transaction);
    match result {
        Ok(transaction_response) => println!("Transaction successful: {:?}", transaction_response),
        Err(error) => println!("Transaction error: {:?}", error),
    }
}

async fn api_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let client = RpcClient::new("https://testnet.solana.com");

    let private_key: String;
    let public_key: String;
    let amount: u64;

    let body = req.into_body();
    let body_bytes = hyper::body::to_bytes(body).await.unwrap();
    let body_string = String::from_utf8(body_bytes.to_vec()).unwrap();
    let body_json: Value = serde_json::from_str(&body_string).unwrap();

    private_key = body_json["private_key"].as_str().unwrap().to_string();
    public_key = body_json["public_key"].as_str().unwrap().to_string();
    amount = body_json["amount"].as_u64().unwrap();

    let private_key_str = private_key.as_str();
    let public_key_str = public_key.as_str();

    let signer = Keypair::from_base58_string(&private_key_str);

    make_airdrop(&public_key_str, amount, &client, &signer);

    Ok(Response::new(Body::from("Airdrop successful")))
}


async fn handle(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("Hello World")))
}

#[tokio::main]
async fn main() {

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    // let new_svc = || {
    //     service_fn(api_handler)
    // };

    let new_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(api_handler))
    });

    let server = Server::bind(&addr).serve(new_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}