use pqc_kyber::{
    decapsulate, encapsulate, keypair, Ake, AkeSendInit, AkeSendResponse, Keypair, PublicKey,
    KYBER_CIPHERTEXTBYTES,
};
use rand::rngs::ThreadRng;

use crate::crypto::KeyNeg;
pub struct KyberDithCipher {
    pub pub_key: [u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
    pub priv_key: [u8; pqc_kyber::KYBER_SECRETKEYBYTES],
    pub shared_secret: Option<[u8; pqc_kyber::KYBER_SSBYTES]>,
}

impl KyberDithCipher {
    pub fn init() -> KyberDithCipher {
        let keypair = keypair(&mut ThreadRng::default()).unwrap();

        KyberDithCipher {
            pub_key: keypair.public,
            priv_key: keypair.secret,
            shared_secret: None,
        }
    }

    pub fn gen_ciphertext(&mut self, pubkey: &[u8]) -> [u8; KYBER_CIPHERTEXTBYTES] {
        let (ciphertext, shared_secret) = encapsulate(pubkey, &mut ThreadRng::default()).unwrap();
        self.shared_secret = Some(shared_secret);

        ciphertext
    }
}

impl KeyNeg for KyberDithCipher {
    fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.to_vec()
    }

    fn gen_shared_secret(self, pub_key: &[u8]) -> Box<[u8]> {
        if pub_key.len() == KYBER_CIPHERTEXTBYTES {
            Box::new(decapsulate(pub_key, &self.priv_key).unwrap())
        } else {
            panic!(
                "gen_shared_secret: not same len!\nfound: {}, expected: {}",
                pub_key.len(),
                KYBER_CIPHERTEXTBYTES
            );
        }
    }
}

#[derive(Clone)]
pub struct KyberCipher {
    pub keys: Keypair,
    pub cipher: Box<Ake>,
}

impl KyberCipher {
    pub fn init() -> KyberCipher {
        let cipher = Ake::new();

        let cipher_keys = keypair(&mut ThreadRng::default()).unwrap();

        KyberCipher {
            cipher: Box::new(cipher),
            keys: cipher_keys,
        }
    }

    pub fn client_init(&mut self, server: PublicKey) -> AkeSendInit {
        self.cipher
            .client_init(&server, &mut ThreadRng::default())
            .unwrap()
    }

    pub fn server_recv(
        &mut self,
        client_init: AkeSendInit,
        client_pubkey: PublicKey,
    ) -> AkeSendResponse {
        self.cipher
            .server_receive(
                client_init,
                &client_pubkey,
                &self.keys.secret,
                &mut ThreadRng::default(),
            )
            .unwrap()
    }

    pub fn client_confirm(&mut self, server_res: AkeSendResponse) {
        self.cipher
            .client_confirm(server_res, &self.keys.secret)
            .unwrap();
    }
}
