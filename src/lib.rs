pub mod app_state;
pub mod crypto;
pub mod server;

pub use crate::app_state::APPSTATE;
use crate::crypto::key_exchange::{ECDHKeys, ECDSAKeys};

#[cfg(test)]
mod tests {
    use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
    use p384::{ecdsa::Signature, PublicKey};

    use crate::crypto::aes::ChaChaCipher;

    use super::*;

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

        let alice_cipher = ChaChaCipher::init_with_key(alice_secret);
        let bob_cipher = ChaChaCipher::init_with_key(bob_secret);

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
        let app_state_keys = &APPSTATE.read().unwrap().ecdsa_server_keys;
        println!(
            "App state: pub: {:#?}, priv: {:#?}",
            app_state_keys.pub_key, app_state_keys.priv_key
        );
    }
}
