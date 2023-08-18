pub mod app_state;
pub mod client;
pub mod config;
pub mod crypto;
pub mod frame;
pub mod server;

pub use crate::app_state::APPSTATE;
use crate::crypto::key_exchange::{ECDHKeys, ECDSAKeys};

#[cfg(test)]
mod tests {
    use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
    use p384::{ecdsa::Signature, ecdsa::VerifyingKey, PublicKey};

    use crate::{
        app_state::ClientKeypair,
        crypto::aes::ChaChaCipher,
        frame::{DataFrame, Frame, InitFrame, Options},
    };

    use super::*;

    fn start_http_server() {
        APPSTATE.write().expect("failed to get write lock").user_id =
            "teo".as_bytes().try_into().unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:3876");
        if let Ok(s) = socket {
            crate::server::http::start_server(s);
        }
    }

    // NOTE: Cannot hold a .write() lock on APPSTATE
    fn generate_keypair(id: String) -> ClientKeypair {
        let app_state = APPSTATE.read().unwrap();
        let ecdsa_keypair = crypto::key_exchange::ECDSAKeys::init();
        let ecdh_keypair = crypto::key_exchange::ECDHKeys::init();

        ClientKeypair::new()
            .ecdsa(ecdsa_keypair.pub_key)
            .ecdh(
                app_state
                    .server_keys
                    .ecdh
                    .priv_key
                    .diffie_hellman(&ecdh_keypair.pub_key),
            )
            .uuid(uuid::Uuid::new_v4())
            .id(id)
    }

    #[test]
    fn test_ecdsa() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let keys = crypto::key_exchange::ECDSAKeys::init();
        let msg = b"Hi ECDSA!";
        let sig: Signature = keys.priv_key.sign(msg);
        assert!(keys.pub_key.verify(msg, &sig).is_ok())
    }

    #[test]
    fn test_ecdh() {
        let alice_keys = crypto::key_exchange::ECDHKeys::init();
        let bob_keys = crypto::key_exchange::ECDHKeys::init();
        let alice_shared = alice_keys.priv_key.diffie_hellman(&bob_keys.pub_key);
        let bob_shared = bob_keys.priv_key.diffie_hellman(&alice_keys.pub_key);
        // assert_ne!(alice_keys.priv_key, bob_keys.priv_key);

        assert_eq!(
            alice_shared.raw_secret_bytes(),
            bob_shared.raw_secret_bytes()
        );
    }

    #[test]
    fn test_auth_ecdh() {
        use chacha20poly1305::aead::Aead;
        use p384::ecdsa::signature::{Signer, Verifier};
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let alice_ecdsa = crypto::key_exchange::ECDSAKeys::init();
        let bob_ecdsa = crypto::key_exchange::ECDSAKeys::init();

        let alice_ecdh = crypto::key_exchange::ECDHKeys::init();
        let bob_ecdh = crypto::key_exchange::ECDHKeys::init();

        let alice_ecdh_pub_key_sec1_bytes = alice_ecdh.pub_key.to_encoded_point(true).to_bytes();
        let bob_ecdh_pub_key_sec1_bytes = bob_ecdh.pub_key.to_encoded_point(true).to_bytes();

        let alice_signed_ecdh_pub_key: Signature =
            alice_ecdsa.priv_key.sign(&alice_ecdh_pub_key_sec1_bytes);

        let bob_signed_ecdh_pub_key: Signature =
            bob_ecdsa.priv_key.sign(&bob_ecdh_pub_key_sec1_bytes);

        assert!(alice_ecdsa
            .pub_key
            .verify(&alice_ecdh_pub_key_sec1_bytes, &alice_signed_ecdh_pub_key)
            .is_ok());

        assert!(bob_ecdsa
            .pub_key
            .verify(&bob_ecdh_pub_key_sec1_bytes, &bob_signed_ecdh_pub_key)
            .is_ok());

        assert!(alice_ecdsa
            .pub_key
            .verify(&alice_ecdh_pub_key_sec1_bytes, &bob_signed_ecdh_pub_key)
            .is_err());

        // Simulates signed keys being sent over the network,
        // then converted to public keys.
        let returned_alice_ecdh_pub_key =
            PublicKey::from_sec1_bytes(&alice_ecdh_pub_key_sec1_bytes)
                .expect("failed to instantiate pub key from bytes!");
        let returned_bob_ecdh_pub_key = PublicKey::from_sec1_bytes(&bob_ecdh_pub_key_sec1_bytes)
            .expect("failed to instantiate pub key from bytes!");

        let alice_secret = alice_ecdh
            .priv_key
            .diffie_hellman(&returned_bob_ecdh_pub_key);
        let bob_secret = bob_ecdh
            .priv_key
            .diffie_hellman(&returned_alice_ecdh_pub_key);

        println!("length of dh: {}", alice_secret.raw_secret_bytes().len());

        assert_eq!(
            alice_secret.raw_secret_bytes(),
            bob_secret.raw_secret_bytes()
        );

        let alice_cipher = ChaChaCipher::init_with_key(&alice_secret);
        let bob_cipher = ChaChaCipher::init_with_key(&bob_secret);

        let plaintext = "hi bob!";

        let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
        let enc_plaintext = alice_cipher
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .unwrap();

        let dec_plaintext_bytes = bob_cipher.cipher.decrypt(&nonce, &*enc_plaintext).unwrap();
        let dec_plaintext = std::str::from_utf8(&dec_plaintext_bytes).unwrap();

        assert_eq!(plaintext, dec_plaintext);
        println!(
            "alice plaintext = {}, bob dec plaintext = {}",
            plaintext, dec_plaintext
        );
    }

    #[test]
    fn test_appstate() {
        let app_state_keys = &APPSTATE.read().unwrap().server_keys;
        println!(
            "App state: pub: {:#?}, priv: {:#?}",
            app_state_keys.ecdsa.pub_key, app_state_keys.ecdsa.priv_key
        );
    }

    #[test]
    fn test_network_server_pub_key() {
        start_http_server();
        while !APPSTATE.read().unwrap().is_http_server_on {}
        let serv_pub_key = crate::client::http::get_serv_pub("127.0.0.1:3876".parse().unwrap());

        assert_eq!(
            APPSTATE.read().unwrap().server_keys.ecdsa.pub_key,
            serv_pub_key
        );
    }

    #[test]
    fn test_network_init_conn() {
        start_http_server();
        while !APPSTATE.read().unwrap().is_http_server_on {}
        let res = crate::client::http::start_tunnel("127.0.0.1:3876".parse().unwrap());
        let app_state = APPSTATE.read().unwrap();

        let ecdsa_pub_key = app_state.server_keys.ecdsa.pub_key;
        assert_eq!(
            ecdsa_pub_key,
            VerifyingKey::from_sec1_bytes(&res.unwrap().as_bytes()[19..=67]).unwrap()
        );
    }

    #[test]
    fn test_network_msg() -> Result<(), Box<dyn std::error::Error>> {
        start_http_server();
        while !APPSTATE.read().unwrap().is_http_server_on {}
        //crate::client::http::start_tunnel("127.0.0.1:3876".parse()?)?;
        let res = crate::client::http::msg("127.0.0.1:3876".parse()?, "hello test!")?;
        assert_eq!(res.as_bytes().len(), 0);

        Ok(())
    }

    #[test]
    fn test_uuid() -> Result<(), Box<dyn std::error::Error>> {
        start_http_server();
        while !APPSTATE.read()?.is_http_server_on {}
        let uuid = APPSTATE.read()?.uuid;
        let init_res = crate::client::http::start_tunnel("127.0.0.1:3876".parse()?)?;
        assert_eq!(uuid, uuid::Uuid::from_slice(&init_res.as_bytes()[3..=18])?);

        Ok(())
    }

    #[test]
    fn test_data_frame_struct() -> Result<(), Box<dyn std::error::Error>> {
        let aaa_keys = generate_keypair(String::from("aaa"));
        let bbb_keys = generate_keypair(String::from("bbb"));

        // NOTE: WRITE HELD!
        let mut appstate_rw = APPSTATE.write()?;
        appstate_rw.client_keys.push(aaa_keys);
        appstate_rw.client_keys.push(bbb_keys);
        drop(appstate_rw);
        // NOTE: WRITE DROPPED!

        let app_state = APPSTATE.read()?;

        let first_pair = app_state
            .client_keys
            .iter()
            .find(|i| i.id.as_ref().ok_or("failed to get id as bytes").unwrap() == "aaa")
            .ok_or("could not find keypair")?;
        let mut encrypted_frame = DataFrame {
            id: Some(
                first_pair
                    .id
                    .as_ref()
                    .ok_or("could not get id")?
                    .as_bytes()
                    .try_into()?,
            ),
            uuid: Some(first_pair.uuid.into_bytes()),
            body: Box::new(*b"Hello Server!"),
            options: Options::default(),
        };

        println!("encoding frame ...");
        encrypted_frame.encode_frame(first_pair.uuid)?;
        println!("decoding frame ...");
        encrypted_frame.decode_frame()?;

        Ok(())
    }

    #[test]
    fn verify_init_frame() -> Result<(), Box<dyn std::error::Error>> {
        let init_frame = InitFrame::default();
        let init_frame_2 = InitFrame::default();
        init_frame.from_peer(&init_frame_2.to_bytes()).unwrap();
        Ok(())
    }
}
