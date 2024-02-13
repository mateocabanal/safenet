pub mod aes;
pub mod dilithium;
pub mod kyber;

pub trait PubKey: Sync + Send {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait KeyNeg: Sync + Send + Downcast{
    fn to_bytes(&self) -> Vec<u8>;
    fn gen_shared_secret(self, pub_key: &[u8]) -> Box<[u8]>;
}
impl_downcast!(KeyNeg);

impl PubKey for key_exchange::ECDSAPubKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let sig = key_exchange::Signature::from_der(signature)?;
        self.verify(msg, &sig)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl KeyNeg for key_exchange::ECDHKeys {
    fn to_bytes(&self) -> Vec<u8> {
        self.get_pub_key_to_bytes()
    }

    fn gen_shared_secret(self, pub_key: &[u8]) -> Box<[u8]> {
        self.gen_shared_secret_from_key(&key_exchange::ECDHPubKey::from_sec1_bytes(pub_key).unwrap())
            .raw_secret_bytes()
            .into_boxed_slice()
    }
}

#[cfg(not(feature = "ring"))]
mod rust_crypto;

use std::any::Any;
use downcast_rs::{Downcast, impl_downcast};
#[cfg(not(feature = "ring"))]
pub use rust_crypto::key_exchange;

#[cfg(feature = "ring")]
mod ring;
#[cfg(feature = "ring")]
pub use ring::key_exchange;
