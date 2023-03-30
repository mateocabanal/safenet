// use aes_gcm_siv::{
//     aead::{Aead, KeyInit, OsRng},
//     Aes256GcmSiv,
//     Nonce, // Or `Aes128GcmSiv`
// };
use blake2::Blake2s256;
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, KeyInit};
use p384::{elliptic_curve::ecdh::SharedSecret, NistP384};
use pbkdf2::password_hash::{PasswordHasher, SaltString};

#[derive(Clone)]
pub struct ChaChaCipher {
    pub cipher: ChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn init_with_key(dh_secret: &SharedSecret<NistP384>) -> ChaChaCipher {
        use blake2::Digest;

        let mut hasher = Blake2s256::new();
        let dh_bytes = dh_secret.raw_secret_bytes();
        hasher.update(dh_bytes);
        let dh_hashed_bytes = hasher.finalize();

        // let aes_cipher = Aes256GcmSiv::new();
        let cha_cipher = ChaCha20Poly1305::new(&dh_hashed_bytes);

        ChaChaCipher { cipher: cha_cipher }
    }
}
