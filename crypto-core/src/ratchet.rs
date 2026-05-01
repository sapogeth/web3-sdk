///
/// STVOR Web3 — Double Ratchet (Signal Protocol)
///
/// X3DH session establishment + Double Ratchet encrypt/decrypt.
/// Header layout (85 bytes): ratchet_pub(65) | prev_count(4) | msg_num(4) | nonce(12)
///
use crate::crypto::{
    KeyPair, CryptoError, kdf_rk, kdf_ck, aead_encrypt, aead_decrypt, ecdh_secret,
    hybrid_x3dh_initiate, hybrid_x3dh_respond,
};
use crate::pqc::{EK_SIZE, DK_SIZE, CT_SIZE};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Error as DeError;
use std::collections::HashMap;

const PUB_LEN: usize = 65;
const HEADER_LEN: usize = 85; // 65 + 4 + 4 + 12
const MAX_SKIP: u32 = 256;

// ─── Serde helpers for fixed-size byte arrays ─────────────────────────────────

fn ser_bytes65<S: Serializer>(v: &[u8; 65], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}
fn de_bytes65<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 65], D::Error> {
    let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
    v.try_into().map_err(|_| D::Error::custom("expected 65 bytes"))
}
fn ser_bytes32<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}
fn de_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
    v.try_into().map_err(|_| D::Error::custom("expected 32 bytes"))
}
fn ser_opt_bytes65<S: Serializer>(v: &Option<[u8; 65]>, s: S) -> Result<S::Ok, S::Error> {
    match v { Some(b) => s.serialize_some(b.as_slice()), None => s.serialize_none() }
}
fn de_opt_bytes65<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 65]>, D::Error> {
    let v: Option<Vec<u8>> = serde::de::Deserialize::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(b) => b.try_into().map(Some).map_err(|_| D::Error::custom("expected 65 bytes")),
    }
}
fn ser_opt_bytes32<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
    match v { Some(b) => s.serialize_some(b.as_slice()), None => s.serialize_none() }
}
fn de_opt_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
    let v: Option<Vec<u8>> = serde::de::Deserialize::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(b) => b.try_into().map(Some).map_err(|_| D::Error::custom("expected 32 bytes")),
    }
}
fn ser_map_bytes32<S: Serializer>(v: &HashMap<String, [u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = s.serialize_map(Some(v.len()))?;
    for (k, val) in v { map.serialize_entry(k, val.as_slice())?; }
    map.end()
}
fn de_map_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<HashMap<String, [u8; 32]>, D::Error> {
    let raw: HashMap<String, Vec<u8>> = serde::de::Deserialize::deserialize(d)?;
    raw.into_iter()
        .map(|(k, v)| v.try_into().map(|b| (k, b)).map_err(|_| D::Error::custom("expected 32 bytes")))
        .collect()
}

// ─── Session ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    #[serde(serialize_with = "ser_bytes65", deserialize_with = "de_bytes65")]
    pub my_identity_public_key: [u8; 65],
    #[serde(serialize_with = "ser_bytes65", deserialize_with = "de_bytes65")]
    pub peer_identity_public_key: [u8; 65],
    #[serde(serialize_with = "ser_bytes32", deserialize_with = "de_bytes32")]
    root_key: [u8; 32],
    #[serde(serialize_with = "ser_bytes32", deserialize_with = "de_bytes32")]
    sending_chain_key: [u8; 32],
    #[serde(serialize_with = "ser_bytes32", deserialize_with = "de_bytes32")]
    receiving_chain_key: [u8; 32],
    #[serde(serialize_with = "ser_bytes65", deserialize_with = "de_bytes65")]
    my_ratchet_pub: [u8; 65],
    #[serde(serialize_with = "ser_bytes32", deserialize_with = "de_bytes32")]
    my_ratchet_priv: [u8; 32],
    #[serde(serialize_with = "ser_opt_bytes65", deserialize_with = "de_opt_bytes65")]
    their_ratchet_pub: Option<[u8; 65]>,
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,
    #[serde(serialize_with = "ser_map_bytes32", deserialize_with = "de_map_bytes32")]
    skipped_keys: HashMap<String, [u8; 32]>,
    #[serde(serialize_with = "ser_opt_bytes65", deserialize_with = "de_opt_bytes65")]
    peer_spk: Option<[u8; 65]>,
    #[serde(serialize_with = "ser_opt_bytes65", deserialize_with = "de_opt_bytes65")]
    my_spk_pub: Option<[u8; 65]>,
    #[serde(serialize_with = "ser_opt_bytes32", deserialize_with = "de_opt_bytes32")]
    my_spk_priv: Option<[u8; 32]>,
    #[serde(serialize_with = "ser_opt_bytes32", deserialize_with = "de_opt_bytes32")]
    pre_init_root_key: Option<[u8; 32]>,
    sent_before_recv: bool,

    // ── ML-KEM-768 hybrid fields ──────────────────────────────────────────────
    // Stored only on the responder side until the first message is received.
    // After session is established, these are cleared to save memory.
    #[serde(
        serialize_with = "crate::pqc::ser_opt_ct",
        deserialize_with = "crate::pqc::de_opt_ct",
        default
    )]
    pending_mlkem_ct: Option<[u8; CT_SIZE]>,   // initiator stores ct until session confirmed
}

impl Session {
    fn new_from_key(
        my_ik: &KeyPair,
        my_spk: &KeyPair,
        peer_ik: &[u8; 65],
        peer_spk: &[u8; 65],
        shared_key: [u8; 32],
        pending_mlkem_ct: Option<[u8; CT_SIZE]>,
    ) -> Self {
        let ratchet_kp = KeyPair::generate();
        Session {
            my_identity_public_key: my_ik.public_key,
            peer_identity_public_key: *peer_ik,
            root_key: shared_key,
            sending_chain_key: [0u8; 32],
            receiving_chain_key: [0u8; 32],
            my_ratchet_pub: ratchet_kp.public_key,
            my_ratchet_priv: ratchet_kp.private_key,
            their_ratchet_pub: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
            peer_spk: Some(*peer_spk),
            my_spk_pub: Some(my_spk.public_key),
            my_spk_priv: Some(my_spk.private_key),
            pre_init_root_key: Some(shared_key),
            sent_before_recv: false,
            pending_mlkem_ct,
        }
    }

    /// Classic X3DH session (no PQC). Kept for backwards compatibility.
    pub fn establish(
        my_ik: &KeyPair,
        my_spk: &KeyPair,
        peer_ik: &[u8; 65],
        peer_spk: &[u8; 65],
        shared_key: [u8; 32],
    ) -> Self {
        Self::new_from_key(my_ik, my_spk, peer_ik, peer_spk, shared_key, None)
    }

    /// Hybrid X3DH + ML-KEM-768 — initiator side.
    /// Returns (session, mlkem_ct) — send mlkem_ct to peer in the handshake.
    pub fn establish_hybrid_initiator(
        my_ik:         &KeyPair,
        my_spk:        &KeyPair,
        peer_ik:       &[u8; 65],
        peer_spk:      &[u8; 65],
        peer_mlkem_ek: &[u8; EK_SIZE],
    ) -> Result<(Self, [u8; CT_SIZE]), CryptoError> {
        let res = hybrid_x3dh_initiate(my_ik, my_spk, peer_ik, peer_spk, peer_mlkem_ek)?;
        let session = Self::new_from_key(
            my_ik, my_spk, peer_ik, peer_spk,
            res.shared_key,
            None,
        );
        Ok((session, res.mlkem_ct))
    }

    /// Hybrid X3DH + ML-KEM-768 — responder side.
    /// Accepts the mlkem_ct sent by the initiator in the handshake.
    pub fn establish_hybrid_responder(
        my_ik:       &KeyPair,
        my_spk:      &KeyPair,
        peer_ik:     &[u8; 65],
        peer_spk:    &[u8; 65],
        my_mlkem_dk: &[u8; DK_SIZE],
        mlkem_ct:    &[u8; CT_SIZE],
    ) -> Result<Self, CryptoError> {
        let shared_key = hybrid_x3dh_respond(
            my_ik, my_spk, peer_ik, peer_spk, my_mlkem_dk, mlkem_ct,
        )?;
        Ok(Self::new_from_key(my_ik, my_spk, peer_ik, peer_spk, shared_key, None))
    }

    // ── Encrypt ──────────────────────────────────────────────────────────────

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Deferred init: initiator DH ratchet on first send
        if self.their_ratchet_pub.is_none() {
            if let Some(peer_spk) = self.peer_spk.take() {
                let dh_out = ecdh_secret(&self.my_ratchet_priv, &peer_spk)?;
                let (new_rk, new_ck) = kdf_rk(&self.root_key, &dh_out);
                self.root_key = new_rk;
                self.sending_chain_key = new_ck;
                self.their_ratchet_pub = Some(peer_spk);
                self.sent_before_recv = true;
            }
        }

        let (new_ck, message_key) = kdf_ck(&self.sending_chain_key);
        self.sending_chain_key = new_ck;

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut header = [0u8; HEADER_LEN];
        header[..PUB_LEN].copy_from_slice(&self.my_ratchet_pub);
        header[PUB_LEN..PUB_LEN+4].copy_from_slice(&self.prev_send_count.to_be_bytes());
        header[PUB_LEN+4..PUB_LEN+8].copy_from_slice(&self.send_count.to_be_bytes());
        header[PUB_LEN+8..].copy_from_slice(&nonce);

        let ciphertext = aead_encrypt(&message_key, plaintext, &nonce, &header);
        self.send_count += 1;

        // Format: header(85) | ciphertext
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────

    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if message.len() < HEADER_LEN {
            return Err(CryptoError::DecryptionFailed);
        }

        let header: [u8; HEADER_LEN] = message[..HEADER_LEN].try_into().unwrap();
        let ciphertext = &message[HEADER_LEN..];

        let their_pub: [u8; 65] = header[..PUB_LEN].try_into().unwrap();
        let prev_chain = u32::from_be_bytes(header[PUB_LEN..PUB_LEN+4].try_into().unwrap());
        let msg_num    = u32::from_be_bytes(header[PUB_LEN+4..PUB_LEN+8].try_into().unwrap());
        let nonce: [u8; 12] = header[PUB_LEN+8..].try_into().unwrap();

        // Deferred init: pure responder (never sent first)
        if self.their_ratchet_pub.is_none() {
            if let (Some(pub_k), Some(priv_k)) = (self.my_spk_pub.take(), self.my_spk_priv.take()) {
                self.my_ratchet_pub = pub_k;
                self.my_ratchet_priv = priv_k;
                self.peer_spk = None;
                self.pre_init_root_key = None;
            }
        }

        // Check skipped keys
        let skip_id = format!("{}:{}", hex::encode(their_pub), msg_num);
        if let Some(mk) = self.skipped_keys.remove(&skip_id) {
            return aead_decrypt(&mk, ciphertext, &nonce, &header);
        }

        let needs_ratchet = self.their_ratchet_pub
            .map(|p| p != their_pub)
            .unwrap_or(true);

        if needs_ratchet {
            if self.their_ratchet_pub.is_some() {
                self.skip_keys(prev_chain)?;
            }
            self.dh_ratchet_step(&their_pub)?;
            self.pre_init_root_key = None;
        }

        self.skip_keys(msg_num)?;

        let (new_ck, message_key) = kdf_ck(&self.receiving_chain_key);
        self.receiving_chain_key = new_ck;
        self.recv_count += 1;

        aead_decrypt(&message_key, ciphertext, &nonce, &header)
    }

    fn skip_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if until.saturating_sub(self.recv_count) > MAX_SKIP {
            return Err(CryptoError::DecryptionFailed);
        }
        while self.recv_count < until {
            let (new_ck, mk) = kdf_ck(&self.receiving_chain_key);
            self.receiving_chain_key = new_ck;
            let key = format!(
                "{}:{}",
                hex::encode(self.their_ratchet_pub.unwrap_or([0u8; 65])),
                self.recv_count
            );
            self.skipped_keys.insert(key, mk);
            self.recv_count += 1;
        }
        Ok(())
    }

    fn dh_ratchet_step(&mut self, their_new_key: &[u8; 65]) -> Result<(), CryptoError> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.their_ratchet_pub = Some(*their_new_key);

        let dh1 = ecdh_secret(&self.my_ratchet_priv, their_new_key)?;
        let (rk1, recv_ck) = kdf_rk(&self.root_key, &dh1);
        self.root_key = rk1;
        self.receiving_chain_key = recv_ck;

        let new_ratchet = KeyPair::generate();
        let dh2 = ecdh_secret(&new_ratchet.private_key, their_new_key)?;
        let (rk2, send_ck) = kdf_rk(&self.root_key, &dh2);
        self.root_key = rk2;
        self.sending_chain_key = send_ck;
        self.my_ratchet_pub = new_ratchet.public_key;
        self.my_ratchet_priv = new_ratchet.private_key;

        Ok(())
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }
}

// ─── hex helper (avoid external dep) ─────────────────────────────────────────

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, x3dh_symmetric};

    fn make_session_pair() -> (Session, Session) {
        let alice_ik = KeyPair::generate();
        let alice_spk = KeyPair::generate();
        let bob_ik = KeyPair::generate();
        let bob_spk = KeyPair::generate();

        let sk_alice = x3dh_symmetric(&alice_ik, &alice_spk, &bob_ik.public_key, &bob_spk.public_key).unwrap();
        let sk_bob   = x3dh_symmetric(&bob_ik, &bob_spk, &alice_ik.public_key, &alice_spk.public_key).unwrap();

        let alice = Session::establish(&alice_ik, &alice_spk, &bob_ik.public_key, &bob_spk.public_key, sk_alice);
        let bob   = Session::establish(&bob_ik, &bob_spk, &alice_ik.public_key, &alice_spk.public_key, sk_bob);

        (alice, bob)
    }

    #[test]
    fn test_alice_sends_bob_receives() {
        let (mut alice, mut bob) = make_session_pair();
        let msg = b"Hello, Bob from TON!";
        let encrypted = alice.encrypt(msg).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_bob_replies() {
        let (mut alice, mut bob) = make_session_pair();

        let enc1 = alice.encrypt(b"Hi Bob").unwrap();
        bob.decrypt(&enc1).unwrap();

        let enc2 = bob.encrypt(b"Hey Alice!").unwrap();
        let dec2 = alice.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"Hey Alice!");
    }

    #[test]
    fn test_multiple_messages() {
        let (mut alice, mut bob) = make_session_pair();
        for i in 0u8..10 {
            let msg = vec![i; 32];
            let enc = alice.encrypt(&msg).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            assert_eq!(dec, msg);
        }
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = make_session_pair();
        for i in 0u8..5 {
            let a_msg = format!("alice-{}", i).into_bytes();
            let enc = alice.encrypt(&a_msg).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            assert_eq!(dec, a_msg);

            let b_msg = format!("bob-{}", i).into_bytes();
            let enc = bob.encrypt(&b_msg).unwrap();
            let dec = alice.decrypt(&enc).unwrap();
            assert_eq!(dec, b_msg);
        }
    }

    #[test]
    fn test_session_serialization() {
        let (mut alice, mut bob) = make_session_pair();

        let enc1 = alice.encrypt(b"init").unwrap();
        bob.decrypt(&enc1).unwrap();

        let json = bob.to_json().unwrap();
        let mut restored = Session::from_json(&json).unwrap();

        let enc2 = alice.encrypt(b"after restore").unwrap();
        let dec2 = restored.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"after restore");
    }
}
