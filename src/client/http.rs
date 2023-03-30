use std::net::SocketAddr;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chacha20poly1305::aead::Aead;
use minreq::Response;
use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};

use crate::{app_state::ClientKeypair, crypto::key_exchange::ECDHKeys, APPSTATE};

pub fn get_serv_pub(peer: SocketAddr) -> VerifyingKey {
    let peer_addr = peer.to_string();
    let res = minreq::get(format!("http://{peer_addr}/keys/pub"))
        .send()
        .unwrap();
    let serv_ecdh = VerifyingKey::from_sec1_bytes(res.as_bytes()).unwrap();

    serv_ecdh
}

pub fn start_tunnel(peer: SocketAddr) -> Result<Response, Box<dyn std::error::Error>> {
    let peer_addr = peer.to_string();
    let ecdsa_pub_key = APPSTATE
        .read()
        .unwrap()
        .server_keys
        .ecdsa
        .pub_key
        .to_encoded_point(true);
    let ecdh_keys = ECDHKeys::init();
    let ecdh_pub_key_sec1 = ecdh_keys.pub_key.to_encoded_point(true).to_bytes();
    let signed_ecdh_pub: Signature = APPSTATE
        .write()
        .unwrap()
        .server_keys
        .ecdsa
        .priv_key
        .sign(&ecdh_pub_key_sec1);
    let user_id = "teo".as_bytes();

    log::trace!(
        "id len: {}, ecdsa len: {}, ecdh_key len: {}, sig len: {}",
        user_id.len(),
        ecdsa_pub_key.as_bytes().len(),
        ecdh_pub_key_sec1.len(),
        &signed_ecdh_pub.to_der().as_bytes().len()
    );
    log::trace!("key: {:#?}", &signed_ecdh_pub);
    let body = [
        user_id,
        ecdsa_pub_key.as_bytes(),
        &ecdh_pub_key_sec1,
        &signed_ecdh_pub.to_der().as_bytes(),
    ]
    .concat()
    .to_vec();
    log::trace!("body len: {}", body.len());
    let res = minreq::post(format!("http://{peer_addr}/conn/init"))
        .with_body(body)
        .send()?;

    let body_bytes = res.clone().into_bytes();
    log::trace!("len of res: {}", body_bytes.len());
    let id = &body_bytes[0..=2];

    let client_ecdsa_key = VerifyingKey::from_sec1_bytes(&body_bytes[3..=51]).unwrap();
    let client_ecdh_key_bytes = &body_bytes[52..=100];
    let client_signature = Signature::from_der(&body_bytes[101..]).unwrap();
    log::trace!("server res: key: {:#?}", client_signature);
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

    let client_keypair = ClientKeypair::new()
        .id(std::str::from_utf8(id)
            .expect("failed to parse id")
            .to_string())
        .ecdsa(client_ecdsa_key)
        .ecdh(client_server_shared_secret);
    APPSTATE
        .write()
        .expect("failed to get write lock")
        .client_keys
        .push(client_keypair);
    Ok(res)
}

pub fn msg<T: Into<String>>(peer: SocketAddr, msg: T) -> Response {
    let peer_addr_str = peer.to_string();

    let id = "teo".as_bytes();
    let app_state = APPSTATE.read().expect("failed to get read lock");
    let shared_secret_bytes = app_state
        .client_keys
        .first()
        .expect("failed to get write lock")
        .ecdh
        .as_ref()
        .unwrap()
        .raw_secret_bytes();

    log::debug!("client shared_secret_bytes: {:#?}", &shared_secret_bytes);

    let mut hasher = Blake2bVar::new(12).unwrap();
    let mut buf = [0u8; 12];
    hasher.update(&shared_secret_bytes);
    hasher.finalize_variable(&mut buf).unwrap();
    log::debug!("buf: {:#?}", &buf);

    let enc_msg = app_state
        .client_keys
        .first()
        .unwrap()
        .chacha
        .as_ref()
        .unwrap()
        .cipher
        .encrypt(
            generic_array::GenericArray::from_slice(&buf),
            msg.into().as_bytes(),
        );
    if let Err(e) = enc_msg {
        log::error!("could not encyrpt msg, {}", e);
    }

    let res = minreq::post(format!("http://{peer_addr_str}/conn/test"))
        .with_body([id.to_vec(), enc_msg.unwrap()].concat())
        .send()
        .unwrap();

    res
}
