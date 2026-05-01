///
/// STVOR Web3 — Crypto primitives (Rust)
///
/// P-256 ECDH + ECDSA, AES-256-GCM, HKDF-SHA256, HMAC-SHA256
/// Pure Rust — zero C dependencies.
///
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier},
    elliptic_curve::{sec1::ToEncodedPoint, ecdh::diffie_hellman},
    PublicKey, SecretKey,
};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::Sha256;
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub public_key: [u8; 65],   // uncompressed P-256
    pub private_key: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(point.as_bytes());

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&secret.to_bytes());

        KeyPair { public_key, private_key }
    }

    pub fn from_bytes(private_key: &[u8; 32]) -> Result<Self, CryptoError> {
        let secret = SecretKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(point.as_bytes());

        Ok(KeyPair {
            public_key,
            private_key: *private_key,
        })
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    DecryptionFailed,
    InvalidSignature,
    InvalidPublicKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey => write!(f, "Invalid key"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

// ─── ECDH ─────────────────────────────────────────────────────────────────────

pub fn ecdh_secret(private_key: &[u8; 32], public_key: &[u8; 65]) -> Result<[u8; 32], CryptoError> {
    let secret = SecretKey::from_slice(private_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let public = PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());

    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_ref());
    Ok(out)
}

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────────

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    h.expand(info, &mut out).expect("HKDF expand failed");
    out
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac::<Sha256> as HmacKeyInit>::new_from_slice(key).expect("HMAC key error");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

// ─── Chain Key KDF (Signal-style) ─────────────────────────────────────────────

pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_chain_key = hmac_sha256(chain_key, &[0x01]);
    let message_key   = hmac_sha256(chain_key, &[0x02]);
    (new_chain_key, message_key)
}

// ─── Root Key KDF ─────────────────────────────────────────────────────────────

pub fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let out = hkdf_sha256(dh_out, root_key, b"stvor-rk", 64);
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk, ck)
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

pub fn aead_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .expect("AES-GCM encrypt failed")
}

pub fn aead_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ─── ECDSA P-256 ──────────────────────────────────────────────────────────────

pub fn ec_sign(data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, CryptoError> {
    let secret = SecretKey::from_slice(&key_pair.private_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let signing_key = SigningKey::from(secret);
    let sig: Signature = signing_key.sign(data);
    Ok(sig.to_der().to_bytes().to_vec())
}

pub fn ec_verify(data: &[u8], sig_der: &[u8], public_key: &[u8; 65]) -> Result<bool, CryptoError> {
    let public = PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from(public);
    let sig = Signature::from_der(sig_der)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(verifying_key.verify(data, &sig).is_ok())
}

// ─── X3DH Symmetric ──────────────────────────────────────────────────────────

pub fn x3dh_symmetric(
    my_ik: &KeyPair,
    my_spk: &KeyPair,
    peer_ik: &[u8; 65],
    peer_spk: &[u8; 65],
) -> Result<[u8; 32], CryptoError> {
    let dh1 = ecdh_secret(&my_ik.private_key, peer_ik)?;
    let i_am_lower = my_ik.public_key < *peer_ik;
    let dh2 = if i_am_lower {
        ecdh_secret(&my_ik.private_key, peer_spk)?
    } else {
        ecdh_secret(&my_spk.private_key, peer_ik)?
    };
    let dh3 = if i_am_lower {
        ecdh_secret(&my_spk.private_key, peer_ik)?
    } else {
        ecdh_secret(&my_ik.private_key, peer_spk)?
    };

    let lower_ik = if i_am_lower { &my_ik.public_key } else { peer_ik };
    let upper_ik = if i_am_lower { peer_ik } else { &my_ik.public_key };

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let mut salt = b"X3DH-SALT".to_vec();
    salt.extend_from_slice(lower_ik);
    salt.extend_from_slice(upper_ik);

    let sk = hkdf_sha256(&ikm, &salt, b"X3DH-SK", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sk);
    Ok(out)
}

// ─── Hybrid X3DH + ML-KEM-768 ────────────────────────────────────────────────
//
// Shared secret = HKDF(ecdh_sk ‖ mlkem_ss, "STVOR-HYBRID-v1")
//
// Security: quantum-safe if EITHER ECDH OR ML-KEM is secure.
//   - ECDH (P-256) guards against classical attacks
//   - ML-KEM-768 guards against quantum attacks
//
// Initiator: calls hybrid_x3dh_initiate() → gets (shared_key, mlkem_ct)
//   then sends mlkem_ct to responder alongside normal X3DH handshake
// Responder: calls hybrid_x3dh_respond() with mlkem_ct → gets shared_key

use crate::pqc::{mlkem_encaps, mlkem_decaps, EK_SIZE, DK_SIZE, CT_SIZE};

pub struct HybridInitResult {
    pub shared_key: [u8; 32],
    pub mlkem_ct:   [u8; CT_SIZE],   // 1088 bytes — send to responder
}

/// Initiator side: X3DH(P-256) + ML-KEM encaps → hybrid shared key
pub fn hybrid_x3dh_initiate(
    my_ik:         &KeyPair,
    my_spk:        &KeyPair,
    peer_ik:       &[u8; 65],
    peer_spk:      &[u8; 65],
    peer_mlkem_ek: &[u8; EK_SIZE],
) -> Result<HybridInitResult, CryptoError> {
    // Classical X3DH
    let ecdh_sk = x3dh_symmetric(my_ik, my_spk, peer_ik, peer_spk)?;

    // ML-KEM-768 encapsulation
    let pqc_res = mlkem_encaps(peer_mlkem_ek)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Combine: HKDF(ecdh_sk ‖ mlkem_ss, "STVOR-HYBRID-v1")
    let shared_key = hybrid_kdf(&ecdh_sk, &pqc_res.shared_key);

    Ok(HybridInitResult {
        shared_key,
        mlkem_ct: pqc_res.ciphertext,
    })
}

/// Responder side: X3DH(P-256) + ML-KEM decaps → hybrid shared key
pub fn hybrid_x3dh_respond(
    my_ik:      &KeyPair,
    my_spk:     &KeyPair,
    peer_ik:    &[u8; 65],
    peer_spk:   &[u8; 65],
    my_mlkem_dk: &[u8; DK_SIZE],
    mlkem_ct:   &[u8; CT_SIZE],
) -> Result<[u8; 32], CryptoError> {
    // Classical X3DH
    let ecdh_sk = x3dh_symmetric(my_ik, my_spk, peer_ik, peer_spk)?;

    // ML-KEM-768 decapsulation
    let mlkem_ss = mlkem_decaps(my_mlkem_dk, mlkem_ct)
        .map_err(|_| CryptoError::InvalidKey)?;

    Ok(hybrid_kdf(&ecdh_sk, &mlkem_ss))
}

/// HKDF combiner: HKDF-SHA256(ikm = ecdh_sk ‖ mlkem_ss, salt = zeros, info = "STVOR-HYBRID-v1")
fn hybrid_kdf(ecdh_sk: &[u8; 32], mlkem_ss: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ecdh_sk);
    ikm[32..].copy_from_slice(mlkem_ss);
    let out = hkdf_sha256(&ikm, &[0u8; 32], b"STVOR-HYBRID-v1", 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key[0], 0x04, "Uncompressed point must start with 0x04");
        assert_eq!(kp.public_key.len(), 65);
        assert_eq!(kp.private_key.len(), 32);
    }

    #[test]
    fn test_ecdh_symmetric() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let s1 = ecdh_secret(&kp1.private_key, &kp2.public_key).unwrap();
        let s2 = ecdh_secret(&kp2.private_key, &kp1.public_key).unwrap();
        assert_eq!(s1, s2, "ECDH must produce the same shared secret");
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let pt = b"hello stvor web3";
        let ct = aead_encrypt(&key, pt, &nonce, b"aad");
        let dec = aead_decrypt(&key, &ct, &nonce, b"aad").unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_ecdsa_roundtrip() {
        let kp = KeyPair::generate();
        let data = b"stvor web3 identity";
        let sig = ec_sign(data, &kp).unwrap();
        let ok = ec_verify(data, &sig, &kp.public_key).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_ecdsa_reject_wrong_data() {
        let kp = KeyPair::generate();
        let sig = ec_sign(b"hello", &kp).unwrap();
        let ok = ec_verify(b"hellx", &sig, &kp.public_key).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_x3dh_symmetric() {
        let alice_ik = KeyPair::generate();
        let alice_spk = KeyPair::generate();
        let bob_ik = KeyPair::generate();
        let bob_spk = KeyPair::generate();

        let sk_alice = x3dh_symmetric(&alice_ik, &alice_spk, &bob_ik.public_key, &bob_spk.public_key).unwrap();
        let sk_bob = x3dh_symmetric(&bob_ik, &bob_spk, &alice_ik.public_key, &alice_spk.public_key).unwrap();

        assert_eq!(sk_alice, sk_bob, "X3DH must produce the same shared key for both parties");
    }

    #[test]
    fn test_hybrid_x3dh_both_sides_agree() {
        use crate::pqc::mlkem_keygen;

        let alice_ik  = KeyPair::generate();
        let alice_spk = KeyPair::generate();
        let bob_ik    = KeyPair::generate();
        let bob_spk   = KeyPair::generate();
        let bob_pqc   = mlkem_keygen();

        // Alice initiates hybrid session toward Bob
        let res = hybrid_x3dh_initiate(
            &alice_ik, &alice_spk,
            &bob_ik.public_key, &bob_spk.public_key,
            &bob_pqc.encapsulation_key,
        ).unwrap();

        // Bob responds using his DK and Alice's CT
        let bob_sk = hybrid_x3dh_respond(
            &bob_ik, &bob_spk,
            &alice_ik.public_key, &alice_spk.public_key,
            &bob_pqc.decapsulation_key,
            &res.mlkem_ct,
        ).unwrap();

        assert_eq!(res.shared_key, bob_sk, "Hybrid X3DH must produce same key on both sides");
    }

    #[test]
    fn test_hybrid_x3dh_differs_from_classical() {
        use crate::pqc::mlkem_keygen;

        let alice_ik  = KeyPair::generate();
        let alice_spk = KeyPair::generate();
        let bob_ik    = KeyPair::generate();
        let bob_spk   = KeyPair::generate();
        let bob_pqc   = mlkem_keygen();

        let classical = x3dh_symmetric(
            &alice_ik, &alice_spk, &bob_ik.public_key, &bob_spk.public_key,
        ).unwrap();

        let hybrid = hybrid_x3dh_initiate(
            &alice_ik, &alice_spk, &bob_ik.public_key, &bob_spk.public_key,
            &bob_pqc.encapsulation_key,
        ).unwrap();

        assert_ne!(classical, hybrid.shared_key, "Hybrid key must differ from classical X3DH");
    }

    #[test]
    fn test_hybrid_session_full_roundtrip() {
        use crate::pqc::mlkem_keygen;
        use crate::ratchet::Session;

        let alice_ik  = KeyPair::generate();
        let alice_spk = KeyPair::generate();
        let bob_ik    = KeyPair::generate();
        let bob_spk   = KeyPair::generate();
        let bob_pqc   = mlkem_keygen();

        // Alice creates hybrid session → gets mlkem_ct to send to Bob
        let (mut alice_session, mlkem_ct) = Session::establish_hybrid_initiator(
            &alice_ik, &alice_spk,
            &bob_ik.public_key, &bob_spk.public_key,
            &bob_pqc.encapsulation_key,
        ).unwrap();

        // Bob creates hybrid session using the ct from Alice
        let mut bob_session = Session::establish_hybrid_responder(
            &bob_ik, &bob_spk,
            &alice_ik.public_key, &alice_spk.public_key,
            &bob_pqc.decapsulation_key,
            &mlkem_ct,
        ).unwrap();

        // Alice sends, Bob receives
        let msg = b"Quantum-safe hello from TON!";
        let enc = alice_session.encrypt(msg).unwrap();
        let dec = bob_session.decrypt(&enc).unwrap();
        assert_eq!(dec, msg, "Hybrid session message must decrypt correctly");

        // Bob replies, Alice receives
        let reply = b"Hybrid E2EE works!";
        let enc2 = bob_session.encrypt(reply).unwrap();
        let dec2 = alice_session.decrypt(&enc2).unwrap();
        assert_eq!(dec2, reply, "Hybrid session reply must decrypt correctly");
    }
}
