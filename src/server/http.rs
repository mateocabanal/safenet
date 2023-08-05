use std::net::TcpListener;
use std::net::{IpAddr, SocketAddr};

use blake2::{digest::Update, digest::VariableOutput, Blake2bVar};
use chacha20poly1305::aead::Aead;
use local_ip_address::local_ip;
use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use tinyhttp::prelude::*;
use uuid::Uuid;

use crate::frame::DataFrame;
use crate::{app_state::ClientKeypair, crypto::key_exchange::ECDHKeys, APPSTATE};

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
    //    let headers = req.get_headers();
    //    let host_res = headers.get("x-forwarded-for");
    //    if let None = host_res {
    //        return Response::new()
    //            .body("nice try loser :)".as_bytes().to_vec())
    //            .status_line("403 Forbidden HTTP/1.1");
    //    };
    let id = &body_bytes[0..=2];
    let data_frame = DataFrame::try_from(body_bytes);

    if let Err(_) = data_frame {
        return Response::new()
            .body(b"nice try :)".to_vec())
            .status_line("403 Forbidden HTTP/1.1");
    }

    let data_frame = data_frame.unwrap();

    //    #[cfg(debug_assertions)]
    //    log::debug!("id: {}, ip: {}", std::str::from_utf8(id).unwrap(), host_res.unwrap());
    //    if *host_res.unwrap() == format!("0.0.0.0:{}", APPSTATE.read().unwrap().server_addr.unwrap().port()) {
    //        log::debug!("host_res == 0.0.0.0")
    //    }

    if body_bytes.len() < 197 {
        return Response::new()
            .body("nice try loser :)".as_bytes().to_vec())
            .status_line("403 Forbidden HTTP/1.1");
    }
    //log::trace!("client res: id: {}", std::str::from_utf8(id).unwrap());
    //    let client_uuid = Uuid::from_slice(&body_bytes[3..=18]).unwrap();
    let client_uuid = Uuid::from_bytes(data_frame.uuid.unwrap());
    log::trace!("client uuid: {}", client_uuid);

    let client_ecdsa_key = VerifyingKey::from_sec1_bytes(&body_bytes[19..=67]).unwrap();
    let client_ecdh_key_bytes = &body_bytes[68..=116];
    let client_signature = Signature::from_der(&body_bytes[117..]).unwrap();
    log::trace!("client res: key: {:#?}", client_signature);
    if client_ecdsa_key
        .verify(client_ecdh_key_bytes, &client_signature)
        .is_err()
    {
        log::debug!("SIG FAILED :(");
    }

    let client_ecdh_key = PublicKey::from_sec1_bytes(client_ecdh_key_bytes).unwrap();
    let new_ecdh = ECDHKeys::init();
    let client_server_shared_secret = new_ecdh.priv_key.diffie_hellman(&client_ecdh_key);

    log::trace!(
        "server secret as bytes: {:#?}",
        &client_server_shared_secret.raw_secret_bytes()
    );
    let is_preexisting = APPSTATE
        .read()
        .unwrap()
        .client_keys
        .iter()
        .position(|i| i.uuid == client_uuid);
    if let Some(s) = is_preexisting {
        log::trace!("client uuid already exists, overwriting...");
        APPSTATE.write().unwrap().client_keys.remove(s);
    };
    //    let is_preexisting_ip = APPSTATE
    //        .read()
    //        .unwrap()
    //        .client_keys
    //        .iter()
    //        .position(|i| i.ip.unwrap() == host);
    //
    //    if let Some(s) = is_preexisting_ip {
    //        log::trace!("client ip already exists, overwriting...");
    //        APPSTATE.write().unwrap().client_keys.remove(s);
    //    };

    let new_client_keypair = ClientKeypair::new()
        .id(std::str::from_utf8(id).unwrap().to_string())
        .ecdsa(client_ecdsa_key)
        .uuid(client_uuid)
        .ecdh(client_server_shared_secret);
    APPSTATE
        .write()
        .expect("failed to write-lock state!")
        .client_keys
        .push(new_client_keypair);

    let app_state = APPSTATE.read().expect("Failed to get read lock");
    let id = app_state.user_id.as_ref();
    let srv_ecdsa_pub_key = app_state
        .server_keys
        .ecdsa
        .pub_key
        .to_encoded_point(true)
        .to_bytes();
    let srv_ecdh_bytes = new_ecdh.pub_key.to_encoded_point(true).to_bytes();

    let srv_ecdh_sig: Signature = app_state.server_keys.ecdsa.priv_key.sign(&srv_ecdh_bytes);
    let server_uuid = app_state.uuid.as_bytes();
    let body = [
        id,
        server_uuid,
        &srv_ecdsa_pub_key,
        &srv_ecdh_bytes,
        srv_ecdh_sig.to_der().as_bytes(),
    ]
    .to_vec()
    .concat();

    //let new_user_ecdsa_pub_key = &body_bytes[3..=52];
    //log::trace!("written response!");

    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(body)
        .mime("fuck/off")
}

#[post("/conn/test")]
fn msg(req: Request) -> Response {
    let req_bytes = req.get_raw_body();
    let data_frame: Result<DataFrame, String> = req_bytes.try_into();
    if data_frame.is_err() {
        return Response::new()
            .body(vec![])
            .mime("fuck/off")
            .status_line("HTTP/1.1 42069 fuck_u");
    }
    let mut data_frame = data_frame.unwrap();
//    let id = std::str::from_utf8(&req_bytes[0..=2]).unwrap();
//    let client_uuid = Uuid::from_slice(&req_bytes[3..=18]).unwrap();
//    let app_state = APPSTATE.read().expect("failed to get read lock!");
//
//    let client_keys = app_state
//        .client_keys
//        .iter()
//        .find(|i| i.uuid == client_uuid)
//        .unwrap();
//
//    let dec_key = client_keys.chacha.as_ref().unwrap();
//    let shared_secret_bytes = client_keys.ecdh.as_ref().unwrap().raw_secret_bytes();
//    //   log::debug!("id: {}", id);
//    log::debug!("shared_secret: {:#?}", &shared_secret_bytes);
//
//    let body = &req_bytes[19..];
//
//    let mut hasher = Blake2bVar::new(12).unwrap();
//    let mut buf = [0u8; 12];
//    hasher.update(&shared_secret_bytes);
//    hasher.finalize_variable(&mut buf).unwrap();
//    let dec_body = dec_key
//        .cipher
//        .decrypt(generic_array::GenericArray::from_slice(&buf), body);
    let uuid = Uuid::from_bytes(data_frame.uuid.unwrap());
    let dec_body = data_frame.decode_frame(uuid);

    if dec_body.is_ok() {
        let id = std::str::from_utf8(data_frame.id.as_ref().unwrap()).unwrap();
        println!(
            "\n***\nfrom: {}, {}\n***",
            id,
            std::str::from_utf8(&data_frame.body).unwrap()
        );

        Response::new()
            .mime("fuck/off")
            .status_line("HTTP/1.1 403 Forbidden")
            .body("".as_bytes().to_vec())
    } else {
        log::error!("failed to decrypt msg! uuid: {}", uuid);
        Response::new()
            .mime("fuck/me")
            .status_line("HTTP/1.1 42069 fuck_me")
            .body("".as_bytes().to_vec())
    }
}

#[post("/server/echo")]
fn server_msg(req: Request) -> Response {
    let req_bytes = req.get_raw_body();
    let data_frame: Result<DataFrame, String> = req_bytes.try_into();
    if data_frame.is_err() {
        return Response::new()
            .body(vec![])
            .mime("fuck/off")
            .status_line("HTTP/1.1 42069 fuck_u");
    }
    let mut data_frame = data_frame.unwrap();

    /*
    let id = &req_bytes[0..=2];
    let client_uuid = Uuid::from_slice(&req_bytes[3..=18]).unwrap();
    let app_state = APPSTATE.read().expect("failed to get read lock!");

    let client_keys = app_state
        .client_keys
        .iter()
        .find(|i| i.uuid == client_uuid)
        .unwrap();

    let dec_key = client_keys.chacha.as_ref().unwrap();
    let shared_secret_bytes = client_keys.ecdh.as_ref().unwrap().raw_secret_bytes();
    //   log::debug!("id: {}", id);
    log::debug!("shared_secret: {:#?}", &shared_secret_bytes);

    let body = &req_bytes[19..];

    let mut hasher = Blake2bVar::new(12).unwrap();
    let mut buf = [0u8; 12];
    hasher.update(&shared_secret_bytes);
    hasher.finalize_variable(&mut buf).unwrap();
    let dec_body = dec_key
        .cipher
        .decrypt(generic_array::GenericArray::from_slice(&buf), body);
    */

    let uuid = Uuid::from_bytes(data_frame.uuid.unwrap());
    let dec_body = data_frame.decode_frame(uuid);

    if dec_body.is_ok() {
        let msg = String::from_utf8(data_frame.body).unwrap();
        Response::new()
            .body(format!("Got it, {msg}").as_bytes().to_vec())
            .mime("love/u")
            .status_line("HTTP/1.1 200 OK")
    } else {
        Response::new()
            .body(vec![])
            .mime("fuck/u")
            .status_line("HTTP/1.1 42069 fuck_me")
    }
}

pub fn start_server(socket: TcpListener) {
    let local_ip = local_ip().unwrap();
    log::debug!("Started HTTP Server");
    let routes = vec![init_conn(), get_pub_key(), msg(), server_msg()];
    let conf = Config::new().routes(Routes::new(routes));
    APPSTATE
        .write()
        .expect("failed to get write lock")
        .server_addr = Some(SocketAddr::new(
        IpAddr::V4(local_ip.to_string().parse().unwrap()),
        socket.local_addr().unwrap().port(),
    ));
    log::trace!(
        "server_addr: {}",
        APPSTATE.read().unwrap().server_addr.unwrap()
    );
    let http = HttpListener::new(socket, conf);

    std::thread::spawn(move || {
        http.start();
    });
    std::thread::sleep(std::time::Duration::from_millis(500));

    APPSTATE.write().unwrap().is_http_server_on = true;
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_init_frame() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
