use p384::{
    ecdh::EphemeralSecret,
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    EncodedPoint, NistP384, PublicKey,
};

use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct ECDSAKeys {
    pub pub_key: VerifyingKey,
    pub priv_key: SigningKey,
}

pub struct ECDHKeys {
    pub pub_key: PublicKey,
    pub priv_key: EphemeralSecret,
}

impl ECDSAKeys {
    pub fn init() -> ECDSAKeys {
        let priv_key = SigningKey::random(&mut OsRng);
        let pub_key = VerifyingKey::from(&priv_key);
        ECDSAKeys { pub_key, priv_key }
    }
}

impl ECDHKeys {
    pub fn init() -> ECDHKeys {
        let priv_key = EphemeralSecret::random(&mut OsRng);
        let pub_key =
            PublicKey::from_sec1_bytes(EncodedPoint::from(priv_key.public_key()).as_ref())
                .expect("Failed to generate ECDH public key!");
        ECDHKeys { pub_key, priv_key }
    }

    pub fn init_with_params<T, U>(pub_key: U, priv_key: T) -> ECDHKeys
    where
        T: Into<EphemeralSecret>,
        U: Into<PublicKey>,
    {
        let pub_key = pub_key.into();
        let priv_key = priv_key.into();
        ECDHKeys { pub_key, priv_key }
    }
}
