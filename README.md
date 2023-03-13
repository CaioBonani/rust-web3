# rust-web3
Rust API to interact with Solana network.

This API was built to be used within [Solana-token-trade](https://github.com/CaioBonani/solana-token-trade).

To run this API you I'll need to create a self-signed SSL/TLS certificate (API runs in HTTPS), and change the .pem files to match the file name hardcoded in the program. In my case I just used the mkcert (https://github.com/FiloSottile/mkcert) tool, instead of the openssl standard tool. The .pem files need to be in the root of the project.

After cloning the repository and generating the certificate run `cargo run`. This will download all the project's dependencies (crates), compile and run the server. Make sure you have the cargo installed, just download Rust (https://www.rust-lang.org/tools/install).
