use pqc_kyber::{Ake, Keypair, keypair, PublicKey, AkeSendInit, AkeSendResponse};
use rand::rngs::ThreadRng;

#[derive(Clone)]
pub struct KyberCipher {
    keys: Keypair,
    cipher: Box<Ake>,
}

impl KyberCipher {
    pub fn init() -> KyberCipher {
        let cipher = Ake::new();
        
        let cipher_keys = keypair(&mut ThreadRng::default()).unwrap();
        
        KyberCipher { cipher: Box::new(cipher), keys: cipher_keys }
    }

    pub fn client_init(&mut self, server: PublicKey) -> AkeSendInit {
        self.cipher.client_init(&server, &mut ThreadRng::default()).unwrap()
    }

    pub fn server_send(&mut self, client_init: AkeSendInit, client_pubkey: PublicKey) -> AkeSendResponse {
        self.cipher.server_receive(client_init, &client_pubkey, &self.keys.secret, &mut ThreadRng::default()).unwrap()
    }

    pub fn client_confirm(&mut self, server_res: AkeSendResponse) {
        self.cipher.client_confirm(server_res, &self.keys.secret).unwrap();
    }
}
