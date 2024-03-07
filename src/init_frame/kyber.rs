use pqc_kyber::{AKE_INIT_BYTES, AKE_RESPONSE_BYTES, KYBER_PUBLICKEYBYTES};
use uuid::Uuid;

use crate::{
    app_state::ClientKeypair,
    crypto::kyber::KyberCipher,
    frame::{EncryptionType, Frame, FrameType, InitFrame, InitOptions},
    options::Options,
    APPSTATE,
};

pub struct KyberInitFrame {
    pub id: [u8; 3],
    pub uuid: Uuid,
    pub options: Options,
    pub body: Vec<u8>,
    pub kyber: KyberCipher,
    pub kyber_nonce: KyberCipher,
}

impl Frame for KyberInitFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let opts_bytes: Vec<u8> = self.options.clone().into();
        [
            self.id.as_slice(),
            self.uuid.as_bytes(),
            &(opts_bytes.len() as u32).to_be_bytes(),
            opts_bytes.as_slice(),
            self.body.as_slice(),
        ]
        .concat()
    }

    fn from_bytes<T>(bytes: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
        Self: Sized,
    {
        let bytes = bytes.as_ref();
        let id = bytes[0..3].try_into()?;
        let uuid = Uuid::from_slice(&bytes[3..19]).unwrap();
        let opts_len = u32::from_be_bytes(bytes[19..23].try_into()?);

        let options = Options::try_from(&bytes[23usize..23 + opts_len as usize])?;

        let body = bytes[23 + opts_len as usize..].to_vec();

        Ok(KyberInitFrame {
            id,
            uuid,
            options,
            body,
            kyber: KyberCipher::init(),
            kyber_nonce: KyberCipher::init(),
        })
    }
}

impl KyberInitFrame {
    pub fn new() -> KyberInitFrame {
        let appstate = APPSTATE.get().unwrap().read().unwrap();

        let id = appstate.user_id;
        let uuid = appstate.uuid;
        let options = Options {
            frame_type: FrameType::Init,
            init_opts: Some(InitOptions::new_with_enc_type(EncryptionType::Kyber).status(0)),
            ..Default::default()
        };

        let kyber = KyberCipher::init();

        KyberInitFrame {
            id,
            uuid,
            options,
            body: vec![],
            kyber,
            kyber_nonce: KyberCipher::init(),
        }
    }

    pub fn from_peer<T>(&mut self, peer_frame: T) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
    {
        let bytes = peer_frame.as_ref();
        let client_uuid = Uuid::from_slice(&bytes[3..19])?;
        let opts_len = u32::from_be_bytes(bytes[19..23].try_into().unwrap()) as usize;
        let opts = Options::try_from(&bytes[23usize..23usize + opts_len])?;

        let body_index = opts_len + 23;
        let init_opts = opts.get_init_opts().unwrap();
        let kyber = &mut self.kyber;
        let kyber_nonce = &mut self.kyber_nonce;
        let body = &bytes[body_index..];

        match init_opts.get_encryption_type().unwrap() {
            EncryptionType::KyberDith => InitFrame::new(EncryptionType::KyberDith).from_peer(bytes),
            EncryptionType::Legacy => InitFrame::default().from_peer(bytes),
            EncryptionType::Kyber => {
                let status = init_opts.get_status();
                log::debug!("kyber init frame with status: {status}");

                match status {
                    0 => {
                        let pub_key = kyber.keys.public;
                        let pub_key_nonce = kyber_nonce.keys.public;
                        let options = Options {
                            frame_type: FrameType::Init,
                            init_opts: Some(
                                InitOptions::new_with_enc_type(EncryptionType::Kyber)
                                    .status(1)
                                    .nonce_secondary_key(true),
                            ),
                            ..Default::default()
                        };

                        let opts_bytes: Vec<u8> = options.into();

                        Ok([
                            [0, 0, 0].as_slice(),
                            APPSTATE.get().unwrap().read()?.uuid.as_bytes(),
                            &(opts_bytes.len() as u32).to_be_bytes(),
                            &opts_bytes,
                            &pub_key,
                            &pub_key_nonce,
                        ]
                        .concat())
                    }
                    1 => {
                        let options = Options {
                            frame_type: FrameType::Init,
                            init_opts: Some(
                                InitOptions::new_with_enc_type(EncryptionType::Kyber)
                                    .status(2)
                                    .nonce_secondary_key(true),
                            ),
                            ..Default::default()
                        };
                        let opts_bytes: Vec<u8> = options.into();
                        let appstate_rw = APPSTATE.get().ok_or("could not get appstate")?.read()?;

                        let self_uuid = *appstate_rw.uuid.as_bytes();

                        let client_init =
                            kyber.client_init(body[..KYBER_PUBLICKEYBYTES].try_into()?);
                        let client_init_nonce =
                            kyber_nonce.client_init(body[KYBER_PUBLICKEYBYTES..].try_into()?);
                        Ok([
                            [0, 0, 0].as_slice(),
                            &self_uuid,
                            &(opts_len as u32).to_be_bytes(),
                            &opts_bytes,
                            &kyber.keys.public,
                            &client_init,
                            &kyber_nonce.keys.public,
                            &client_init_nonce,
                        ]
                        .concat())
                    }
                    2 => {
                        let options = Options {
                            frame_type: FrameType::Init,
                            init_opts: Some(
                                InitOptions::new_with_enc_type(EncryptionType::Kyber)
                                    .status(3)
                                    .nonce_secondary_key(true),
                            ),
                            ..Default::default()
                        };
                        let opts_bytes: Vec<u8> = options.into();
                        let mut appstate_rw =
                            APPSTATE.get().ok_or("could not get appstate")?.write()?;

                        if body.len() != (KYBER_PUBLICKEYBYTES + AKE_INIT_BYTES) * 2 {
                            log::error!(
                                "kyber frame is of {} length, should be: {}",
                                body.len(),
                                KYBER_PUBLICKEYBYTES + AKE_INIT_BYTES * 2
                            );
                            return Err("kyber frame is incorrect len".into());
                        }

                        log::debug!("server: body size {}", body.len());
                        log::debug!("KYBER_PUBLICKEYBYTES: {KYBER_PUBLICKEYBYTES}"); // 1568
                        log::debug!("AKE_INIT_BYTES: {AKE_INIT_BYTES}"); // 3136

                        let client_pub_key = &body[..KYBER_PUBLICKEYBYTES];
                        let client_init =
                            &body[KYBER_PUBLICKEYBYTES..AKE_INIT_BYTES + KYBER_PUBLICKEYBYTES];

                        let client_pub_key_nonce = &body[AKE_INIT_BYTES + KYBER_PUBLICKEYBYTES
                            ..(KYBER_PUBLICKEYBYTES * 2) + AKE_INIT_BYTES];
                        let client_init_nonce =
                            &body[(KYBER_PUBLICKEYBYTES * 2) + AKE_INIT_BYTES..];

                        let server_recv =
                            kyber.server_recv(client_init.try_into()?, client_pub_key.try_into()?);

                        let server_recv_nonce = kyber_nonce.server_recv(
                            client_init_nonce.try_into().expect("could not slice in"),
                            client_pub_key_nonce.try_into().expect("could not slice in"),
                        );

                        let client_keypair = ClientKeypair::new()
                            .kyber(kyber.cipher.shared_secret)
                            .nonce_key(Some(kyber_nonce.cipher.shared_secret))
                            .uuid(client_uuid)
                            .id(std::str::from_utf8(&bytes[0..3]).unwrap().to_string());
                        appstate_rw.client_keys.insert(client_uuid, client_keypair);

                        Ok([
                            [0, 0, 0].as_slice(),
                            appstate_rw.uuid.as_bytes(),
                            &(opts_bytes.len() as u32).to_be_bytes(),
                            &opts_bytes,
                            &server_recv,
                            &server_recv_nonce,
                        ]
                        .concat())
                    }
                    3 => {
                        let mut appstate_rw =
                            APPSTATE.get().ok_or("could not get appstate")?.write()?;

                        if body.len() != AKE_RESPONSE_BYTES * 2 {
                            log::error!(
                                "kyber frame is of {} length, should be: {}",
                                body.len(),
                                AKE_RESPONSE_BYTES * 2
                            );
                            return Err("kyber frame is incorrect len".into());
                        }

                        kyber.client_confirm(body[..AKE_RESPONSE_BYTES].try_into()?);
                        kyber_nonce.client_confirm(body[AKE_RESPONSE_BYTES..].try_into()?);

                        let client_keypair = ClientKeypair::new()
                            .kyber(kyber.cipher.shared_secret)
                            .nonce_key(Some(kyber_nonce.cipher.shared_secret))
                            .uuid(client_uuid)
                            .id(std::str::from_utf8(&bytes[0..3]).unwrap().to_string());
                        appstate_rw.client_keys.insert(client_uuid, client_keypair);

                        Ok(vec![])
                    }
                    _ => Err("status number is invalid".into()),
                }
            }
        }
    }
}

impl Default for KyberInitFrame {
    fn default() -> Self {
        KyberInitFrame::new()
    }
}
