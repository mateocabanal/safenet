
use p384::{PublicKey, NistP384, ecdsa::VerifyingKey};

pub fn get_serv_pub() -> VerifyingKey {
    let res = minreq::get("http://127.0.0.1:3876/keys/pub").send().unwrap();
    let serv_ecdh = VerifyingKey::from_sec1_bytes(res.as_bytes()).unwrap();

    serv_ecdh
}
