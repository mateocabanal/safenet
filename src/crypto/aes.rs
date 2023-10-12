// use aes_gcm_siv::{
//     aead::{Aead, KeyInit, OsRng},
//     Aes256GcmSiv,
//     Nonce, // Or `Aes128GcmSiv`
// };
use blake2::{digest::consts::U32, Blake2b, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use super::key_exchange::SharedSecret;

type Blake2b256 = Blake2b<U32>;

#[derive(Clone)]
pub struct ChaChaCipher {
    pub cipher: ChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn init_with_key(dh_secret: &SharedSecret) -> ChaChaCipher {
        let mut hasher = Blake2b256::new();

        let dh_bytes = dh_secret.raw_secret_bytes();
        hasher.update(dh_bytes);
        let dh_hashed_bytes = hasher.finalize();

        // let aes_cipher = Aes256GcmSiv::new();
        let cha_cipher = ChaCha20Poly1305::new(&dh_hashed_bytes);

        ChaChaCipher { cipher: cha_cipher }
    }
}
