use p384::{
    ecdh::EphemeralSecret,
    ecdsa::{
        signature::{Signer, Verifier},
        SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    EncodedPoint, PublicKey,
};

use rand::rngs::OsRng;

pub struct Signature {
    sig: p384::ecdsa::Signature,
}

impl Signature {
    pub fn from_der(bytes: &[u8]) -> Result<Signature, Box<dyn std::error::Error>> {
        if let Ok(sig) = p384::ecdsa::Signature::from_der(bytes) {
            Ok(Signature { sig })
        } else {
            Err("failed to parse bytes into Signature".into())
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.sig.to_der().to_bytes().to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAPubKey {
    pub_key: VerifyingKey,
}

impl ECDSAPubKey {
    pub fn from_sec1_bytes(pub_key_bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let pub_key_opt = VerifyingKey::from_sec1_bytes(pub_key_bytes);
        if let Ok(pub_key) = pub_key_opt {
            Ok(Self { pub_key })
        } else {
            Err("invalid P-384 key".into())
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pub_key.to_encoded_point(false).as_ref().to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(()) = self.pub_key.verify(msg, &sig.sig) {
            Ok(())
        } else {
            Err("failed to verify signature".into())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ECDSAKeys {
    pub_key: ECDSAPubKey,
    priv_key: SigningKey,
}

pub struct SharedSecret {
    shared_secret: p384::ecdh::SharedSecret,
}

impl SharedSecret {
    /// Use with caution, you probably don't want to be sending this around...
    pub fn raw_secret_bytes(&self) -> Vec<u8> {
        self.shared_secret.raw_secret_bytes().to_vec()
    }
}

#[derive(Clone)]
pub struct ECDHPubKey {
    pub_key: p384::PublicKey,
}

impl ECDHPubKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<ECDHPubKey, Box<dyn std::error::Error>> {
        let pub_key = p384::PublicKey::from_sec1_bytes(bytes);

        if let Ok(pub_key) = pub_key {
            Ok(ECDHPubKey { pub_key })
        } else {
            Err("invalid public key".into())
        }
    }

    pub(self) fn get_pub_key(&self) -> p384::PublicKey {
        self.pub_key
    }

    pub fn get_pub_key_to_bytes(&self) -> Vec<u8> {
        self.pub_key.to_sec1_bytes().to_vec()
    }
}

pub struct ECDHKeys {
    pub_key: ECDHPubKey,
    priv_key: EphemeralSecret,
}

impl ECDSAKeys {
    pub fn init() -> ECDSAKeys {
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key = ECDSAPubKey {
            pub_key: VerifyingKey::from(&priv_key),
        };
        ECDSAKeys { pub_key, priv_key }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature {
            sig: self.priv_key.sign(msg),
        }
    }

    pub fn get_pub_key(&self) -> ECDSAPubKey {
        self.pub_key.clone()
    }

    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let priv_bytes = self.priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        Some(priv_bytes)
    }

    pub fn from_raw_bytes(bytes: &[u8]) -> Result<ECDSAKeys, Box<dyn std::error::Error>> {
        let priv_key = SigningKey::from_pkcs8_der(bytes)?;
        let pub_key = ECDSAPubKey {
            pub_key: priv_key.verifying_key().to_owned(),
        };

        Ok(ECDSAKeys { pub_key, priv_key })
    }
}

impl ECDHKeys {
    pub fn init() -> ECDHKeys {
        let priv_key = EphemeralSecret::random(&mut OsRng);
        let pub_key = ECDHPubKey {
            pub_key: PublicKey::from_sec1_bytes(EncodedPoint::from(priv_key.public_key()).as_ref())
                .expect("Failed to generate ECDH public key!"),
        };
        ECDHKeys { pub_key, priv_key }
    }

    pub fn init_with_params<T, U>(pub_key: U, priv_key: T) -> ECDHKeys
    where
        T: Into<EphemeralSecret>,
        U: Into<PublicKey>,
    {
        let pub_key = ECDHPubKey {
            pub_key: pub_key.into(),
        };
        let priv_key = priv_key.into();
        ECDHKeys { pub_key, priv_key }
    }

    pub fn get_pub_key(&self) -> ECDHPubKey {
        self.pub_key.clone()
    }

    pub fn get_pub_key_to_bytes(&self) -> Vec<u8> {
        self.pub_key
            .pub_key
            .to_encoded_point(false)
            .to_bytes()
            .to_vec()
    }

    pub fn gen_shared_secret_from_key(&self, peer_dh_key: &ECDHPubKey) -> SharedSecret {
        let shared_secret = self.priv_key.diffie_hellman(&peer_dh_key.get_pub_key());
        SharedSecret { shared_secret }
    }
}
