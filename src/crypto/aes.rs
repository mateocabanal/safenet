// use aes_gcm_siv::{
//     aead::{Aead, KeyInit, OsRng},
//     Aes256GcmSiv,
//     Nonce, // Or `Aes128GcmSiv`
// };
use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

use super::key_exchange::SharedSecret;

type Blake2b256 = Blake2b<U32>;

#[derive(Clone)]
pub struct ChaChaCipher {
    pub cipher: XChaCha20Poly1305,
    pub secret_bytes: [u8; 32],
}

impl ChaChaCipher {
    pub fn init_with_key(dh_secret: &SharedSecret) -> ChaChaCipher {
        let mut hasher = Blake2b256::new();

        let dh_bytes = dh_secret.raw_secret_bytes();
        hasher.update(dh_bytes);
        let dh_hashed_bytes = hasher.finalize();

        // let aes_cipher = Aes256GcmSiv::new();
        let cha_cipher = XChaCha20Poly1305::new(&dh_hashed_bytes);

        ChaChaCipher {
            cipher: cha_cipher,
            secret_bytes: dh_hashed_bytes.into(),
        }
    }

    pub fn init_with_raw_bytes(bytes: &[u8]) -> ChaChaCipher {
        let mut hasher = Blake2b256::new();

        hasher.update(bytes);
        let hasher_bytes = hasher.finalize();
        let cipher = XChaCha20Poly1305::new(&hasher_bytes);

        ChaChaCipher {
            cipher,
            secret_bytes: hasher_bytes.into(),
        }
    }
}
