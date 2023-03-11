use std::{io, env, fs, sync};
use std::net::SocketAddr;
use std::str::FromStr;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;
use std::result::Result;
use std::task::ready;
use std::io::prelude::*;


use core::task::{Context, Poll};

// use hyper_tls::native_tls::TlsAcceptor;
use spl_token::ID;
use solana_client::rpc_client::RpcClient;
use solana_sdk::message::Message;
use solana_sdk::{
    signer::keypair::Keypair,
    transaction::Transaction,
    pubkey::Pubkey,
};

use serde_json::Value;

use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{service_fn, make_service_fn};
use hyper::header::{HeaderMap, HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_ALLOW_METHODS, 
                    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_EXPOSE_HEADERS};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use hyper_tls::HttpsConnector;


use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls;
use tokio_rustls::rustls::ServerConfig;


use std::error::Error;

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

pub struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}


//funcoes

fn transfer_token(public_key: &str, amount: u64, client: &RpcClient, signer: &Keypair) {

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

    // let mut response = Response::new(Body::from("Airdrop successful"));

    let mut headers = HeaderMap::new();

    headers.insert(
        ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str("https://localhost:3000/").unwrap(),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_str("POST, GET, OPTIONS").unwrap(),
    );
    headers.insert(
        ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_str("86400").unwrap(),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_str("Content-Type, Authorization").unwrap(),
    );

    // let mut response = Response::new(Body::from("fgsfsgwgw"));

    // // Adiciona cabeçalho "Access-Control-Allow-Origin" com o valor "*"
    // response.headers_mut().insert(
    //     ACCESS_CONTROL_ALLOW_ORIGIN,
    //     HeaderValue::from_str("https://localhost:3000/").unwrap(),
    // );

    // // Adiciona cabeçalho "Access-Control-Allow-Methods" com o valor "POST"
    // response.headers_mut().insert(
    //     ACCESS_CONTROL_ALLOW_METHODS,
    //     HeaderValue::from_str("POST, GET").unwrap(),
    // );

    // response.headers_mut().insert(
    //     ACCESS_CONTROL_MAX_AGE,
    //     HeaderValue::from_str("86400").unwrap(),
    // );

    // response.headers_mut().insert(
    //     ACCESS_CONTROL_ALLOW_HEADERS,
    //     HeaderValue::from_str("*").unwrap(),
    // );


    let body = "Hello, World!";
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(ACCESS_CONTROL_ALLOW_METHODS, "*")
        .header(ACCESS_CONTROL_EXPOSE_HEADERS, "*")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .header(ACCESS_CONTROL_MAX_AGE, "86400")
        .body(Body::from(body))
        .unwrap();


    // let client = RpcClient::new("https://devnet.solana.com");
    
    // let private_key: String;
    // let public_key: String;
    // let amount: u64;
    
    // let body = req.into_body();
    // let body_bytes = hyper::body::to_bytes(body).await.unwrap();
    // let body_string = String::from_utf8(body_bytes.to_vec()).unwrap();
    // let body_json: Value = serde_json::from_str(&body_string).unwrap();

    // private_key = body_json["private_key"].as_str().unwrap().to_string();
    // public_key = body_json["public_key"].as_str().unwrap().to_string();
    // amount = body_json["amount"].as_u64().unwrap();

    // let private_key_str = private_key.as_str();
    // let public_key_str = public_key.as_str();

    // let signer = Keypair::from_base58_string(&private_key_str);

    // transfer_token(&public_key_str, amount, &client, &signer);

    Ok(response)
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<tokio_rustls::rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs
        .into_iter()
        .map(tokio_rustls::rustls::Certificate)
        .collect())
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<tokio_rustls::rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        println!("{}", keys.len());
        return Err(error("expected a single private key".into()));
    }

    Ok(tokio_rustls::rustls::PrivateKey(keys[0].clone()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let tls_cfg = {

        let cert_file = "/home/bonani/iniciacao/rust-web3/localhost.pem";
        let certs = load_certs(cert_file)?;

        let key_file = "/home/bonani/iniciacao/rust-web3/localhost-key.pem";
        let key = load_private_key(key_file)?;

        let mut cfg = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| error(format!("{}", e)))?;
            // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            sync::Arc::new(cfg)
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(api_handler)) });
    let incoming = AddrIncoming::bind(&addr)?;
    let server = Server::builder(TlsAcceptor::new(tls_cfg, incoming)).serve(service);

    println!("Server running in: https://127.0.0.1:8080");

    // Starts the server
    server.await?;

    Ok(())
}