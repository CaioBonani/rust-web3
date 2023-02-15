use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_ALLOW_METHODS};

// ...

async fn api_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // Seu código de handler da API aqui

    let mut response = Response::new(Body::from("Airdrop successful"));

    // Adiciona cabeçalho "Access-Control-Allow-Origin" com o valor "*"
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str("*").unwrap(),
    );

    // Adiciona cabeçalho "Access-Control-Allow-Methods" com o valor "POST"
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_str("POST").unwrap(),
    );

    Ok(response)
}
