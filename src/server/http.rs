use std::{collections::HashMap, net::TcpListener};

use blake2::{Blake2s256, digest::Update, Digest, Blake2bVar, digest::VariableOutput};
use chacha20poly1305::aead::Aead;
use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, ecdh::SharedSecret,
};
use tinyhttp::prelude::*;

use crate::{app_state::ClientKeypair, APPSTATE};

#[get("/keys/pub")]
fn get_pub_key(_req: Request) -> Response {
    let server_pub_key = APPSTATE
        .read()
        .expect("Error getting read lock")
        .server_keys
        .ecdsa
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
    log::trace!("client res: id: {}", std::str::from_utf8(id).unwrap());

    let client_ecdsa_key = VerifyingKey::from_sec1_bytes(&body_bytes[3..=51]).unwrap();
    let client_ecdh_key_bytes = &body_bytes[52..=100];
    let client_signature = Signature::from_der(&body_bytes[101..]).unwrap();
    log::trace!("client res: key: {:#?}", client_signature);
    if client_ecdsa_key
        .verify(client_ecdh_key_bytes, &client_signature)
        .is_err()
    {
        log::trace!("SIG FAILED :(");
    }

    let client_ecdh_key = PublicKey::from_sec1_bytes(&client_ecdh_key_bytes).unwrap();
    let client_server_shared_secret = APPSTATE
        .read()
        .expect("failed to get read lock!")
        .server_keys
        .ecdh
        .priv_key
        .diffie_hellman(&client_ecdh_key);
    let new_client_keypair = ClientKeypair::new()
        .id(std::str::from_utf8(id).unwrap().to_string())
        .ecdsa(client_ecdsa_key)
        .ecdh(client_server_shared_secret);
    APPSTATE
        .write()
        .expect("failed to write-lock state!")
        .client_keys
        .push(new_client_keypair);

    let app_state = APPSTATE.read().expect("Failed to get read lock");
    let id = "srv".as_bytes();
    let srv_ecdsa_pub_key = app_state
        .server_keys
        .ecdsa
        .pub_key
        .to_encoded_point(true)
        .to_bytes();
    let srv_ecdh_bytes = app_state
        .server_keys
        .ecdh
        .pub_key
        .to_encoded_point(true)
        .to_bytes();
    let srv_ecdh_sig: Signature = app_state.server_keys.ecdsa.priv_key.sign(&srv_ecdh_bytes);
    let body = [
        id,
        &srv_ecdsa_pub_key,
        &srv_ecdh_bytes,
        &srv_ecdh_sig.to_der().as_bytes()
    ]
    .to_vec()
    .concat();

    //let new_user_ecdsa_pub_key = &body_bytes[3..=52];
    log::trace!("written response!");

    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(body)
        .mime("fuck/off")
}

#[post("/conn/test")]
fn msg(req: Request) -> Response {
    let req_bytes = req.get_raw_body();
    let id = std::str::from_utf8(&req_bytes[0..=2]).unwrap();
    let app_state = APPSTATE
        .read()
        .expect("failed to get read lock!");
    
    let client_keys = app_state
        .client_keys
        .iter()
        .find(|i| i.id.as_ref().unwrap() == id)
        .unwrap();

    let dec_key = client_keys.chacha.clone().unwrap();
    let shared_secret_bytes = client_keys.ecdh.as_ref().unwrap().raw_secret_bytes();
    log::debug!("id: {}", id);
    log::debug!("shared_secret: {:#?}", &shared_secret_bytes);

    let body = &req_bytes[3..];

    let mut hasher = Blake2bVar::new(12).unwrap();
    let mut buf = [0u8; 12];
    hasher.update(&shared_secret_bytes);
    hasher.finalize_variable(&mut buf).unwrap();
    let dec_body = dec_key.cipher.decrypt(generic_array::GenericArray::from_slice(&buf), body).unwrap();

    println!("from: {}, {}\n", id, std::str::from_utf8(&dec_body).unwrap());

    Response::new()
        .mime("fuck/off")
        .status_line("HTTP/1.1 403 Forbidden")
        .body("".as_bytes().to_vec())
}

pub fn start_server(socket: TcpListener) {
    log::debug!("Started HTTP Server");
    let routes = vec![init_conn(), get_pub_key(), msg()];
    let conf = Config::new().routes(Routes::new(routes));
    let http = HttpListener::new(socket, conf);

    std::thread::spawn(move || {
        http.start();
    });
    std::thread::sleep(std::time::Duration::from_millis(500));

    APPSTATE.write().unwrap().is_http_server_on = true;
}
