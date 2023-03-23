use std::{collections::HashMap, net::TcpListener};

use p384::{PublicKey, ecdsa::{VerifyingKey, signature::Verifier, Signature}};
use tinyhttp::prelude::*;

use crate::APPSTATE;

#[get("/keys/pub")]
fn get_pub_key(_req: Request) -> Response {
    let server_pub_key = APPSTATE
        .read()
        .expect("Error getting read lock")
        .ecdsa_server_keys
        .pub_key
        .to_encoded_point(true);

    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(server_pub_key.as_bytes().to_vec())
        .mime("fuck/off")
}

#[post("/conn/init")]
fn init_conn(req: Request) -> Response {
    let body_bytes = req.get_raw_body();
    if body_bytes.len() < 197 {
        return Response::new()
            .body("nice try loser :)".as_bytes().to_vec())
            .status_line("403 Forbidden HTTP/1.1");
    }
    let id = &body_bytes[0..=2];
    println!("server res: id: {}", std::str::from_utf8(id).unwrap());

    let client_ecdsa_key = VerifyingKey::from_sec1_bytes(&body_bytes[3..=51]).unwrap();
    let client_ecdh_key_bytes = &body_bytes[52..=100];
    let client_signature = Signature::from_der(&body_bytes[101..]).unwrap();
    println!("server res: key: {:#?}", client_signature);
    if client_ecdsa_key.verify(client_ecdh_key_bytes, &client_signature).is_err() {
        println!("SIG FAILED :(");
    }
    //let new_user_ecdsa_pub_key = &body_bytes[3..=52];
    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(
            APPSTATE
                .read()
                .expect("Error getting read lock")
                .ecdsa_server_keys
                .pub_key
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .mime("fuck/off")
}

pub fn start_server(socket: TcpListener) {
    log::debug!("Started HTTP Server");
    let routes = vec![init_conn(), get_pub_key()];
    let conf = Config::new().routes(Routes::new(routes));
    let http = HttpListener::new(socket, conf);

    std::thread::spawn(move || {
        http.start();
    });

    APPSTATE.write().unwrap().is_http_server_on = true;
}
