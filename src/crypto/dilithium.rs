use pqc_dilithium::{verify, Keypair, SignError, PUBLICKEYBYTES};

use crate::crypto::PubKey;

pub struct DilithiumKeyPair {
    keypair: Keypair,
}

impl DilithiumKeyPair {
    pub fn init() -> Self {
        let keypair = Keypair::generate();
        Self { keypair }
    }

    pub fn get_pub(&self) -> DilithiumPubKey {
        DilithiumPubKey::from_bytes(&self.keypair.public).unwrap() // Shouldn't fail
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(msg).to_vec()
    }
}

pub struct DilithiumPubKey {
    pub_key: [u8; PUBLICKEYBYTES],
}

impl DilithiumPubKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<DilithiumPubKey, Box<dyn std::error::Error>> {
        if bytes.len() != PUBLICKEYBYTES {
            Err("length of array does not match expected public key length".into())
        } else {
            Ok(DilithiumPubKey {
                pub_key: bytes.try_into()?,
            })
        }
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignError> {
        verify(signature, msg, &self.pub_key)
    }
}

impl PubKey for DilithiumPubKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(e) = self.verify(msg, signature) {
            Err("verification failed".into())
        } else {
            Ok(())
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.to_vec()
    }
}
