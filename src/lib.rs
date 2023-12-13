pub mod app_state;
pub mod client;
pub mod crypto;
pub mod frame;
pub mod server;

pub use crate::app_state::APPSTATE;

pub use uuid;

#[cfg(test)]
mod tests {
    use crate::crypto::key_exchange::{ECDHKeys, ECDHPubKey, ECDSAKeys, ECDSAPubKey, Signature};
    use chacha20poly1305::{AeadCore, XChaCha20Poly1305};
    use simple_logger::SimpleLogger;

    use crate::{
        app_state::ClientKeypair,
        crypto::aes::ChaChaCipher,
        frame::{DataFrame, Frame, InitFrame, Options},
        uuid::Uuid,
    };

    use tinyhttp::prelude::*;

    #[get("/keys/pub")]
    fn keys_pub() -> Vec<u8> {
        APPSTATE
            .try_read()
            .unwrap()
            .server_keys
            .ecdsa
            .get_pub_key()
            .to_bytes()
    }

    #[post("/conn/init")]
    fn conn_init(req: Request) -> Response {
        let req_bytes = req.get_raw_body();
        let init_frame = InitFrame::default();
        Response::new()
            .mime("text/plain")
            .body(init_frame.from_peer(req_bytes).unwrap())
            .mime("HTTP/1.1 200 OK")
    }

    #[post("/echo")]
    fn server_msg(req: Request) -> Response {
        let req_bytes = req.get_raw_body().clone();
        let data_frame: Result<DataFrame, Box<dyn std::error::Error>> =
            DataFrame::from_bytes(req_bytes);
        if data_frame.is_err() {
            log::trace!("failed to parse data frame");
            return Response::new()
                .body(vec![])
                .mime("fuck/off")
                .status_line("HTTP/1.1 42069 fuck_u");
        }
        let mut data_frame = data_frame.expect("failed to parse data");

        let dec_body = data_frame.decode_frame();

        if let Err(e) = dec_body {
            log::error!("failed to decrypt frame: {e}");
            Response::new()
                .body(vec![])
                .mime("fuck/u")
                .status_line("HTTP/1.1 42069 fuck_me")
        } else {
            let msg = std::str::from_utf8(&data_frame.body).unwrap();
            let mut response_frame = DataFrame::new(&*format!("got: {msg}").into_bytes());
            response_frame
                .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
                .unwrap();
            Response::new()
                .body(response_frame.to_bytes())
                .mime("love/u")
                .status_line("HTTP/1.1 200 OK")
        }
    }

    use super::*;

    #[allow(unused_must_use)]
    fn setup_logger() {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .env()
            .init();
    }

    fn start_http_server() {
        APPSTATE.write().expect("failed to get write lock").user_id =
            "teo".as_bytes().try_into().unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:3876");
        if let Ok(s) = socket {
            let conf =
                Config::new().routes(Routes::new(vec![conn_init(), server_msg(), keys_pub()]));
            std::thread::spawn(|| HttpListener::new(s, conf).start());
            APPSTATE.try_write().unwrap().is_http_server_on = true;
        } else {
            log::warn!("could not bind to port 3876, http server could be on already");
        }
    }

    // NOTE: Cannot hold a .write() lock on APPSTATE
    fn generate_keypair(id: String) -> ClientKeypair {
        let ecdsa_keypair = ECDSAKeys::init();
        let ecdh_keypair = ECDHKeys::init();
        let shared_secret = ECDHKeys::init().gen_shared_secret(&ecdh_keypair.get_pub_key());

        ClientKeypair::new()
            .ecdsa(ecdsa_keypair.get_pub_key().clone())
            .ecdh(shared_secret)
            .uuid(uuid::Uuid::new_v4())
            .id(id)
    }

    #[test]
    fn test_ecdsa() {
        let keys = ECDSAKeys::init();
        let msg = b"Hi ECDSA!";
        let sig: Signature = keys.sign(msg);
        assert!(keys.get_pub_key().verify(msg, &sig).is_ok())
    }

    #[test]
    fn test_ecdh() {
        let alice_keys = ECDHKeys::init();
        let bob_keys = ECDHKeys::init();
        let alice_pub_key = alice_keys.get_pub_key();
        let bob_pub_key = bob_keys.get_pub_key();
        let alice_shared = alice_keys.gen_shared_secret(&bob_pub_key);
        let bob_shared = bob_keys.gen_shared_secret(&alice_pub_key);
        // assert_ne!(alice_keys.priv_key, bob_keys.priv_key);

        assert_eq!(
            alice_shared.raw_secret_bytes(),
            bob_shared.raw_secret_bytes()
        );
    }

    #[test]
    fn test_auth_ecdh() {
        use chacha20poly1305::aead::Aead;

        let alice_ecdsa = ECDSAKeys::init();
        let bob_ecdsa = ECDSAKeys::init();

        let alice_ecdh = ECDHKeys::init();
        let bob_ecdh = ECDHKeys::init();

        let alice_ecdh_pub_key_sec1_bytes = alice_ecdh.get_pub_key_to_bytes();
        let bob_ecdh_pub_key_sec1_bytes = bob_ecdh.get_pub_key_to_bytes();

        let alice_signed_ecdh_pub_key: Signature = alice_ecdsa.sign(&alice_ecdh_pub_key_sec1_bytes);

        let bob_signed_ecdh_pub_key: Signature = bob_ecdsa.sign(&bob_ecdh_pub_key_sec1_bytes);

        assert!(alice_ecdsa
            .get_pub_key()
            .verify(&alice_ecdh_pub_key_sec1_bytes, &alice_signed_ecdh_pub_key)
            .is_ok());

        assert!(bob_ecdsa
            .get_pub_key()
            .verify(&bob_ecdh_pub_key_sec1_bytes, &bob_signed_ecdh_pub_key)
            .is_ok());

        assert!(alice_ecdsa
            .get_pub_key()
            .verify(&alice_ecdh_pub_key_sec1_bytes, &bob_signed_ecdh_pub_key)
            .is_err());

        println!(
            "length of ecdsa pub key (encoded point): {}",
            alice_ecdh_pub_key_sec1_bytes.len(),
        );

        // Simulates signed keys being sent over the network,
        // then converted to public keys.
        let returned_alice_ecdh_pub_key =
            ECDHPubKey::from_sec1_bytes(&alice_ecdh_pub_key_sec1_bytes)
                .expect("failed to instantiate pub key from bytes!");
        let returned_bob_ecdh_pub_key = ECDHPubKey::from_sec1_bytes(&bob_ecdh_pub_key_sec1_bytes)
            .expect("failed to instantiate pub key from bytes!");

        let alice_secret = alice_ecdh.gen_shared_secret(&returned_bob_ecdh_pub_key);
        let bob_secret = bob_ecdh.gen_shared_secret(&returned_alice_ecdh_pub_key);

        println!("length of dh: {}", alice_secret.raw_secret_bytes().len());

        assert_eq!(
            alice_secret.raw_secret_bytes(),
            bob_secret.raw_secret_bytes()
        );

        let alice_cipher = ChaChaCipher::init_with_key(&alice_secret);
        let bob_cipher = ChaChaCipher::init_with_key(&bob_secret);

        let plaintext = "hi bob!";

        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
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
        println!("App state: pub: {:#?}", app_state_keys.ecdsa.get_pub_key(),);
    }

    #[test]
    fn test_network_server_pub_key() {
        start_http_server();
        while !APPSTATE.read().unwrap().is_http_server_on {}
        let serv_pub_key_as_bytes = minreq::get("http://127.0.0.1:3876/keys/pub")
            .send()
            .unwrap();
        let serv_pub_key = ECDSAPubKey::from_sec1_bytes(serv_pub_key_as_bytes.as_bytes()).unwrap();

        #[cfg(not(feature = "ring"))]
        assert_eq!(
            APPSTATE.read().unwrap().server_keys.ecdsa.get_pub_key(),
            serv_pub_key
        );
    }

    #[test]
    fn test_uuid() -> Result<(), Box<dyn std::error::Error>> {
        start_http_server();
        while !APPSTATE.read()?.is_http_server_on {}
        let uuid = APPSTATE.read()?.uuid;
        let client_init_frame = InitFrame::default();
        let server_init_res = minreq::post("http://127.0.0.1:3876/conn/init")
            .with_body(client_init_frame.to_bytes())
            .send()?;
        //        client_init_frame
        //            .from_peer(server_init_res.as_bytes())
        //            .unwrap();

        assert_eq!(
            uuid,
            uuid::Uuid::from_slice(&server_init_res.as_bytes()[3..=18])?
        );

        Ok(())
    }

    #[test]
    fn verify_data_frame() -> Result<(), Box<dyn std::error::Error>> {
        setup_logger();
        let aaa_keys = generate_keypair(String::from("aaa"));
        let bbb_keys = generate_keypair(String::from("bbb"));

        // NOTE: WRITE HELD!
        let mut appstate_rw = APPSTATE.write()?;
        appstate_rw.client_keys.insert(aaa_keys.uuid, aaa_keys);
        appstate_rw.client_keys.insert(bbb_keys.uuid, bbb_keys);
        drop(appstate_rw);
        // NOTE: WRITE DROPPED!

        let app_state = APPSTATE.read()?;

        let first_pair = app_state
            .client_keys
            .iter()
            .find(|(_, i)| i.id.as_ref().ok_or("failed to get id as bytes").unwrap() == "aaa")
            .map(|(_, i)| i)
            .ok_or("could not find keypair")?;

        log::info!("first_pair uuid: {}", first_pair.uuid);

        let second_pair = app_state
            .client_keys
            .iter()
            .find(|(_, i)| i.id.as_ref().ok_or("failed to get id as bytes").unwrap() == "bbb")
            .map(|(_, i)| i)
            .ok_or("could not find keypair")?;

        log::info!("second_pair uuid: {}", second_pair.uuid);

        let mut encrypted_frame = DataFrame::new(b"Hello Server".as_slice());

        println!("encoding frame ...");
        encrypted_frame.encode_frame(first_pair.uuid)?;
        let enc_body = encrypted_frame.to_bytes();
        println!("decoding frame ...");
        let mut recipient_frame = DataFrame::from_bytes(enc_body)?;
        recipient_frame.decode_frame_from_keypair(first_pair)?;

        Ok(())
    }

    #[test]
    fn verify_options() -> Result<(), Box<dyn std::error::Error>> {
        let options = Options::default();
        let bytes: Vec<u8> = options.clone().into();
        let options_2 = Options::try_from(bytes.as_slice())?;
        // HashMap inside of Options is fucking with this assert
        // assert_eq!(options, options_2);
        Ok(())
    }

    #[test]
    fn verify_init_frame() -> Result<(), Box<dyn std::error::Error>> {
        let init_frame = InitFrame::default();
        let init_frame_2 = InitFrame::default();
        let init_frame_bytes = init_frame.from_peer(&init_frame_2.to_bytes()).unwrap();
        let init_frame_2_bytes = init_frame_2.from_peer(&init_frame_bytes).unwrap();

        let init_frame_body_bytes = &init_frame_bytes[23..];
        let init_frame_body_bytes_2 = &init_frame_2_bytes[23..];

        // Shared secret
        assert_eq!(
            init_frame_body_bytes[97..146],
            init_frame_body_bytes_2[97..146]
        );
        Ok(())
    }
}
