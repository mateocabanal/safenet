
use p384::{PublicKey, NistP384, ecdsa::{VerifyingKey, signature::Signer, Signature}, elliptic_curve::sec1::ToEncodedPoint};

use crate::{crypto::key_exchange::ECDHKeys, APPSTATE};

pub fn get_serv_pub() -> VerifyingKey {
    let res = minreq::get("http://127.0.0.1:3876/keys/pub").send().unwrap();
    let serv_ecdh = VerifyingKey::from_sec1_bytes(res.as_bytes()).unwrap();

    serv_ecdh
}

pub fn start_tunnel() {
    let ecdsa_pub_key = APPSTATE.read().unwrap().ecdsa_server_keys.pub_key.to_encoded_point(true);
    let ecdh_keys = ECDHKeys::init();
    let ecdh_pub_key_sec1 = ecdh_keys.pub_key.to_encoded_point(true).to_bytes();
    let signed_ecdh_pub: Signature = APPSTATE.write().unwrap().ecdsa_server_keys.priv_key.sign(&ecdh_pub_key_sec1);
    let user_id = "teo".as_bytes();

    println!("id len: {}, ecdsa len: {}, ecdh_key len: {}, sig len: {}",user_id.len(), ecdsa_pub_key.as_bytes().len(), ecdh_pub_key_sec1.len(), &signed_ecdh_pub.to_der().as_bytes().len());
    println!("key: {:#?}", &signed_ecdh_pub);
    let body = [user_id, ecdsa_pub_key.as_bytes(), &ecdh_pub_key_sec1, &signed_ecdh_pub.to_der().as_bytes()].concat().to_vec();
    println!("body len: {}", body.len());
    let res = minreq::post("http://127.0.0.1:3876/conn/init").with_body(body).send().unwrap();
    println!("response: {}", std::str::from_utf8(res.as_bytes()).unwrap())
}
