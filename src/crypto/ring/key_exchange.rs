use ring::{
    agreement, rand,
    signature::{self, EcdsaKeyPair, KeyPair},
};

pub struct Signature {
    sig: Vec<u8>,
}

impl Signature {
    pub fn from_der(bytes: &[u8]) -> Result<Signature, Box<dyn std::error::Error>> {
        let sig = bytes.to_vec();
        Ok(Signature { sig })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.sig.as_ref()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.sig.to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct ECDSAPubKey {
    pub_key: signature::UnparsedPublicKey<Vec<u8>>,
}

impl ECDSAPubKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<ECDSAPubKey, Box<dyn std::error::Error>> {
        let pub_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, bytes.to_vec());
        Ok(ECDSAPubKey { pub_key })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.as_ref().to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(()) = self.pub_key.verify(msg, sig.as_bytes()) {
            Ok(())
        } else {
            Err("failed to verify signature".into())
        }
    }
}

#[derive(Debug)]
pub struct ECDSAKeys {
    keypair: ring::signature::EcdsaKeyPair,
}

impl ECDSAKeys {
    pub fn init() -> ECDSAKeys {
        let keypair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &rand::SystemRandom::new(),
            )
            .unwrap()
            .as_ref(),
            &rand::SystemRandom::new(),
        )
        .unwrap();
        ECDSAKeys { keypair }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig = self
            .keypair
            .sign(&rand::SystemRandom::new(), msg)
            .unwrap()
            .as_ref()
            .to_vec();

        Signature { sig }
    }

    pub fn get_pub_key(&self) -> ECDSAPubKey {
        let pub_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            self.keypair.public_key().as_ref().to_vec(),
        );
        ECDSAPubKey { pub_key }
    }
}

pub struct ECDHPubKey {
    pub_key: agreement::UnparsedPublicKey<Vec<u8>>,
}

impl ECDHPubKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<ECDHPubKey, Box<dyn std::error::Error>> {
        let pub_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, bytes.to_vec());
        Ok(ECDHPubKey { pub_key })
    }

    pub fn get_pub_key_to_bytes(&self) -> Vec<u8> {
        self.pub_key.as_ref().to_vec()
    }
}

pub struct ECDHKeys {
    priv_key: agreement::EphemeralPrivateKey,
    pub_key: ECDHPubKey,
}

impl ECDHKeys {
    pub fn init() -> ECDHKeys {
        let priv_key = agreement::EphemeralPrivateKey::generate(
            &agreement::ECDH_P384,
            &rand::SystemRandom::new(),
        )
        .unwrap();
        let pub_key =
            ECDHPubKey::from_sec1_bytes(priv_key.compute_public_key().unwrap().as_ref()).unwrap();

        ECDHKeys { pub_key, priv_key }
    }

    pub fn get_pub_key(&self) -> ECDHPubKey {
        let pub_key = agreement::UnparsedPublicKey::new(
            &agreement::ECDH_P384,
            self.pub_key.get_pub_key_to_bytes(),
        );
        ECDHPubKey { pub_key }
    }

    pub fn get_pub_key_to_bytes(&self) -> Vec<u8> {
        self.pub_key.get_pub_key_to_bytes()
    }

    pub fn gen_shared_secret(self, peer_dh_key: &ECDHPubKey) -> SharedSecret {
        log::trace!(
            "len of peer pub dh key: {}",
            peer_dh_key.pub_key.as_ref().len()
        );
        let shared_secret = agreement::agree_ephemeral(
            self.priv_key,
            &peer_dh_key.pub_key,
            |shared_secret_bytes| shared_secret_bytes.to_vec(),
        )
        .unwrap();
        SharedSecret { shared_secret }
    }
}

#[derive(Clone)]
pub struct SharedSecret {
    shared_secret: Vec<u8>,
}

impl SharedSecret {
    pub fn raw_secret_bytes(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}
