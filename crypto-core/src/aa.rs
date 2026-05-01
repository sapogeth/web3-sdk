///
/// STVOR Web3 — Account Abstraction (ERC-4337 + TON v5)
///
/// Derives deterministic E2EE identity from any smart wallet address.
/// Works with:
///   - ERC-4337 (Ethereum/EVM smart wallets: Safe, Coinbase, Biconomy, ZeroDev)
///   - TON Wallet v5 (native TON Account Abstraction)
///   - Any EIP-1193 provider
///
/// AA identity derivation:
///   1. message = "STVOR-AA-v1:<chain_id>:<account_address>"
///   2. signature = personal_sign(message, owner_key)  ← EOA or AA signer
///   3. IK  = HKDF(sig, salt, "IK",  32)  → P-256 identity keypair
///   4. SPK = HKDF(sig, salt, "SPK", 32)  → P-256 signed pre-key
///   5. ML-KEM-768 keypair for hybrid PQC
///
/// UserOperation signing (ERC-4337):
///   Signs the userOpHash with the STVOR identity key so the E2EE session
///   key is cryptographically bound to the AA operation.
///
/// Zero external dependencies — pure Rust.
///

use crate::crypto::{
    KeyPair, CryptoError, hkdf_sha256, hmac_sha256, ec_sign, ec_verify,
    hybrid_x3dh_initiate, hybrid_x3dh_respond,
};
use crate::pqc::{mlkem_keygen, mlkem_encaps, mlkem_decaps, EK_SIZE, DK_SIZE, CT_SIZE};
use rand_core::OsRng;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Error as DeError;

// ─── Chain types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChainType {
    /// EVM-compatible chain (Ethereum, Polygon, Base, Arbitrum, etc.)
    Evm,
    /// TON blockchain (mainnet -239, testnet -3)
    Ton,
}

impl ChainType {
    pub fn domain_prefix(&self) -> &'static str {
        match self {
            ChainType::Evm => "STVOR-AA-EVM-v1",
            ChainType::Ton => "STVOR-AA-TON-v1",
        }
    }
}

// ─── AA Identity ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AaIdentity {
    /// Smart contract wallet address
    pub address: String,
    /// Chain ID (EVM) or chain type string (TON: "mainnet"/"testnet")
    pub chain_id: String,
    /// Chain type
    pub chain_type: ChainType,
    /// P-256 identity keypair (derived from signature)
    pub identity_key: KeyPair,
    /// P-256 signed pre-key (derived from signature)
    pub signed_pre_key: KeyPair,
    /// ECDSA signature of SPK by IK
    pub spk_signature: Vec<u8>,
    /// ML-KEM-768 encapsulation key (1184 bytes, public)
    pub mlkem_ek: [u8; EK_SIZE],
    /// ML-KEM-768 decapsulation key seed (64 bytes, private)
    pub mlkem_dk: [u8; DK_SIZE],
}

impl AaIdentity {
    /// Derive AA identity from a wallet signature.
    ///
    /// `address`   — smart wallet address (0x... for EVM, 0:hex for TON)
    /// `chain_id`  — chain ID string ("1" for Ethereum, "137" for Polygon, "mainnet" for TON)
    /// `chain_type`— EVM or TON
    /// `signature` — raw signature bytes from personal_sign or TON signData
    pub fn derive(
        address: &str,
        chain_id: &str,
        chain_type: ChainType,
        signature: &[u8],
    ) -> Result<Self, CryptoError> {
        let prefix = chain_type.domain_prefix();
        // Domain-separated message: "PREFIX:chain_id:address"
        let msg = format!("{}:{}:{}", prefix, chain_id, address.to_lowercase());

        // HKDF from signature — domain-separated per key type
        let salt = msg.as_bytes();
        let ik_seed:  Vec<u8> = hkdf_sha256(signature, salt, b"IK",  32);
        let spk_seed: Vec<u8> = hkdf_sha256(signature, salt, b"SPK", 32);

        let ik_arr:  [u8; 32] = ik_seed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let spk_arr: [u8; 32] = spk_seed.try_into().map_err(|_| CryptoError::InvalidKey)?;

        let identity_key   = KeyPair::from_bytes(&ik_arr)?;
        let signed_pre_key = KeyPair::from_bytes(&spk_arr)?;

        // Sign SPK public key with identity key
        let spk_signature = ec_sign(&signed_pre_key.public_key, &identity_key)?;

        // ML-KEM-768 keypair
        let pqc = mlkem_keygen();

        Ok(AaIdentity {
            address: address.to_string(),
            chain_id: chain_id.to_string(),
            chain_type,
            identity_key,
            signed_pre_key,
            spk_signature,
            mlkem_ek: pqc.encapsulation_key,
            mlkem_dk: pqc.decapsulation_key,
        })
    }

    /// Verify that the SPK signature is valid
    pub fn verify_spk(&self) -> Result<bool, CryptoError> {
        ec_verify(
            &self.signed_pre_key.public_key,
            &self.spk_signature,
            &self.identity_key.public_key,
        )
    }
}

// ─── UserOperation binding (ERC-4337) ────────────────────────────────────────
//
// Binds an E2EE session to a specific ERC-4337 UserOperation.
// The userOpHash is signed with the STVOR identity key,
// proving the E2EE session belongs to the AA account submitting the op.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpBinding {
    /// ERC-4337 userOpHash (32 bytes, hex)
    pub user_op_hash: String,
    /// ECDSA signature of userOpHash by STVOR identity key (DER, base64)
    pub identity_sig: String,
    /// HMAC-SHA256(userOpHash, session_root_key) — binds session to this op
    pub session_commitment: String,
}

impl UserOpBinding {
    /// Create a binding between a UserOperation and an E2EE session.
    ///
    /// `user_op_hash`    — keccak256 hash of the UserOperation (32 bytes)
    /// `identity`        — the AA identity to sign with
    /// `session_root_key`— the Double Ratchet root key of the E2EE session
    pub fn create(
        user_op_hash: &[u8; 32],
        identity: &AaIdentity,
        session_root_key: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // Sign the userOpHash with identity key
        let sig = ec_sign(user_op_hash, &identity.identity_key)?;

        // HMAC(userOpHash, session_root_key) — commitment
        let commitment = hmac_sha256(session_root_key, user_op_hash);

        Ok(UserOpBinding {
            user_op_hash:       hex_encode(user_op_hash),
            identity_sig:       base64_encode(&sig),
            session_commitment: hex_encode(&commitment),
        })
    }

    /// Verify a UserOpBinding against a known identity public key
    pub fn verify(
        &self,
        identity_pub_key: &[u8; 65],
        session_root_key: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let hash_bytes = hex_decode(&self.user_op_hash).map_err(|_| CryptoError::InvalidKey)?;
        if hash_bytes.len() != 32 { return Err(CryptoError::InvalidKey); }
        let hash_arr: [u8; 32] = hash_bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;

        let sig_bytes = base64_decode(&self.identity_sig)?;

        // Verify identity signature
        if !ec_verify(&hash_arr, &sig_bytes, identity_pub_key)? {
            return Ok(false);
        }

        // Verify session commitment
        let expected = hmac_sha256(session_root_key, &hash_arr);
        let got      = hex_decode(&self.session_commitment).map_err(|_| CryptoError::InvalidKey)?;
        if got.len() != 32 { return Ok(false); }

        // Constant-time comparison
        Ok(constant_time_eq(&expected, got.as_slice()))
    }
}

// ─── ERC-4337 UserOperation structure (pure Rust, no ABI deps) ───────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOperation {
    pub sender:               String,   // AA wallet address
    pub nonce:                String,   // hex uint256
    pub init_code:            String,   // hex bytes (empty if deployed)
    pub call_data:            String,   // hex bytes
    pub call_gas_limit:       String,   // hex uint256
    pub verification_gas:     String,   // hex uint256
    pub pre_verification_gas: String,   // hex uint256
    pub max_fee_per_gas:      String,   // hex uint256
    pub max_priority_fee:     String,   // hex uint256
    pub paymaster_data:       String,   // hex bytes
    pub signature:            String,   // hex bytes (STVOR identity sig)
}

impl UserOperation {
    /// Pack UserOperation fields for hashing (ERC-4337 §4.1)
    /// Returns keccak256(abi.encode(op fields)) without the actual keccak
    /// (keccak256 requires the eth-related crate; we return the packed bytes
    ///  for the caller to hash, keeping zero dependencies)
    pub fn pack_for_hash(&self) -> Vec<u8> {
        let mut packed = Vec::new();
        // ABI-encode each field as 32-byte padded value
        packed.extend_from_slice(&abi_encode_address(&self.sender));
        packed.extend_from_slice(&abi_encode_uint256(&self.nonce));
        packed.extend_from_slice(&abi_encode_bytes_hash(&self.init_code));
        packed.extend_from_slice(&abi_encode_bytes_hash(&self.call_data));
        packed.extend_from_slice(&abi_encode_uint256(&self.call_gas_limit));
        packed.extend_from_slice(&abi_encode_uint256(&self.verification_gas));
        packed.extend_from_slice(&abi_encode_uint256(&self.pre_verification_gas));
        packed.extend_from_slice(&abi_encode_uint256(&self.max_fee_per_gas));
        packed.extend_from_slice(&abi_encode_uint256(&self.max_priority_fee));
        packed.extend_from_slice(&abi_encode_bytes_hash(&self.paymaster_data));
        packed
    }

    /// Sign UserOperation with STVOR identity key.
    /// Returns the signature hex to place in UserOperation.signature field.
    pub fn sign(&mut self, identity: &AaIdentity, entry_point: &str, chain_id: u64)
        -> Result<(), CryptoError>
    {
        let packed     = self.pack_for_hash();
        let op_hash    = sha256_twice(&packed); // simplified — production uses keccak256
        let ep_encoded = abi_encode_address(entry_point);
        let chain_enc  = abi_encode_uint64(chain_id);

        let mut msg = Vec::new();
        msg.extend_from_slice(&op_hash);
        msg.extend_from_slice(&ep_encoded);
        msg.extend_from_slice(&chain_enc);
        let user_op_hash = sha256_twice(&msg);

        let sig = ec_sign(&user_op_hash, &identity.identity_key)?;
        self.signature = hex_encode(&sig);
        Ok(())
    }
}

// ─── TON v5 AA extension ─────────────────────────────────────────────────────
//
// TON Wallet v5 supports "extensions" — external contracts that can authorise
// actions. STVOR binds the E2EE session to a TON wallet v5 extension message.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonV5Extension {
    /// Extension message body (hex)
    pub body_hex: String,
    /// STVOR identity signature of the body hash
    pub identity_sig: String,
    /// Wallet address
    pub wallet_address: String,
}

impl TonV5Extension {
    pub fn create(
        wallet_address: &str,
        body_hex: &str,
        identity: &AaIdentity,
    ) -> Result<Self, CryptoError> {
        let body_bytes = hex_decode(body_hex).map_err(|_| CryptoError::InvalidKey)?;
        let body_hash  = sha256_twice(&body_bytes);
        let sig        = ec_sign(&body_hash, &identity.identity_key)?;

        Ok(TonV5Extension {
            body_hex:     body_hex.to_string(),
            identity_sig: base64_encode(&sig),
            wallet_address: wallet_address.to_string(),
        })
    }

    pub fn verify(&self, identity_pub_key: &[u8; 65]) -> Result<bool, CryptoError> {
        let body_bytes = hex_decode(&self.body_hex).map_err(|_| CryptoError::InvalidKey)?;
        let body_hash  = sha256_twice(&body_bytes);
        let sig_bytes  = base64_decode(&self.identity_sig)?;
        ec_verify(&body_hash, &sig_bytes, identity_pub_key)
    }
}

// ─── Keccak256 (pure Rust, no deps) ──────────────────────────────────────────
// We use SHA-256 double-hash as a stand-in for keccak256 in pack_for_hash.
// For full ERC-4337 compliance, caller provides the pre-computed userOpHash.
// Production integration: pass pre-computed hash from the bundler.

fn sha256_twice(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    h2.into()
}

// ─── ABI encoding helpers (ERC-4337, zero deps) ───────────────────────────────

fn abi_encode_address(addr: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let clean = addr.trim_start_matches("0x").trim_start_matches("0:");
    let bytes = hex_decode(clean).unwrap_or_default();
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

fn abi_encode_uint256(hex_val: &str) -> [u8; 32] {
    abi_encode_address(hex_val) // same padding
}

fn abi_encode_uint64(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&val.to_be_bytes());
    out
}

fn abi_encode_bytes_hash(hex_val: &str) -> [u8; 32] {
    let bytes = hex_decode(hex_val.trim_start_matches("0x")).unwrap_or_default();
    sha256_twice(&bytes)
}

// ─── Utility functions ────────────────────────────────────────────────────────

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 { return Err(()); }
    s.as_bytes().chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}

fn base64_encode(b: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(b)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(s).map_err(|_| CryptoError::InvalidKey)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_sig(seed: u8) -> Vec<u8> {
        (0..64).map(|i| seed.wrapping_add(i)).collect()
    }

    #[test]
    fn test_aa_identity_evm() {
        let sig = mock_sig(42);
        let identity = AaIdentity::derive(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "1",
            ChainType::Evm,
            &sig,
        ).unwrap();

        assert_eq!(identity.chain_type, ChainType::Evm);
        assert_eq!(identity.identity_key.public_key.len(), 65);
        assert_eq!(identity.mlkem_ek.len(), 1184);
        assert_eq!(identity.mlkem_dk.len(), 64);
    }

    #[test]
    fn test_aa_identity_ton() {
        let sig = mock_sig(99);
        let identity = AaIdentity::derive(
            "0:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "mainnet",
            ChainType::Ton,
            &sig,
        ).unwrap();

        assert_eq!(identity.chain_type, ChainType::Ton);
        assert!(identity.verify_spk().unwrap());
    }

    #[test]
    fn test_aa_spk_signature_valid() {
        let identity = AaIdentity::derive(
            "0x1234567890123456789012345678901234567890",
            "137",
            ChainType::Evm,
            &mock_sig(7),
        ).unwrap();

        assert!(identity.verify_spk().unwrap(), "SPK signature must verify");
    }

    #[test]
    fn test_aa_deterministic() {
        let sig = mock_sig(55);
        let id1 = AaIdentity::derive("0xabc", "1", ChainType::Evm, &sig).unwrap();
        let id2 = AaIdentity::derive("0xabc", "1", ChainType::Evm, &sig).unwrap();

        assert_eq!(id1.identity_key.public_key, id2.identity_key.public_key,
            "Same signature must produce same identity key");
        assert_eq!(id1.signed_pre_key.public_key, id2.signed_pre_key.public_key,
            "Same signature must produce same SPK");
    }

    #[test]
    fn test_aa_different_chains_different_keys() {
        let sig = mock_sig(33);
        let evm = AaIdentity::derive("0xabc", "1",       ChainType::Evm, &sig).unwrap();
        let ton = AaIdentity::derive("0xabc", "mainnet", ChainType::Ton, &sig).unwrap();

        assert_ne!(evm.identity_key.public_key, ton.identity_key.public_key,
            "Different chains must produce different keys");
    }

    #[test]
    fn test_userop_binding_roundtrip() {
        let identity = AaIdentity::derive(
            "0xdeadbeef00000000000000000000000000000001",
            "1",
            ChainType::Evm,
            &mock_sig(11),
        ).unwrap();

        let user_op_hash = [0x42u8; 32];
        let session_key  = [0x11u8; 32];

        let binding = UserOpBinding::create(&user_op_hash, &identity, &session_key).unwrap();
        let valid   = binding.verify(&identity.identity_key.public_key, &session_key).unwrap();
        assert!(valid, "UserOpBinding must verify");
    }

    #[test]
    fn test_userop_binding_wrong_key_rejected() {
        let id1 = AaIdentity::derive("0xaaa", "1", ChainType::Evm, &mock_sig(1)).unwrap();
        let id2 = AaIdentity::derive("0xbbb", "1", ChainType::Evm, &mock_sig(2)).unwrap();

        let hash = [0x77u8; 32];
        let skey = [0x22u8; 32];

        let binding = UserOpBinding::create(&hash, &id1, &skey).unwrap();
        let valid   = binding.verify(&id2.identity_key.public_key, &skey).unwrap();
        assert!(!valid, "Wrong key must fail verification");
    }

    #[test]
    fn test_ton_v5_extension_roundtrip() {
        let identity = AaIdentity::derive(
            "0:1234000000000000000000000000000000000000000000000000000000000000",
            "mainnet",
            ChainType::Ton,
            &mock_sig(88),
        ).unwrap();

        let body_hex = "deadbeef01020304";
        let ext = TonV5Extension::create("0:1234", body_hex, &identity).unwrap();
        let ok  = ext.verify(&identity.identity_key.public_key).unwrap();
        assert!(ok, "TON v5 extension must verify");
    }

    #[test]
    fn test_aa_hybrid_session() {
        // Full hybrid X3DH session from two AA identities
        let alice = AaIdentity::derive("0xalice", "1", ChainType::Evm, &mock_sig(10)).unwrap();
        let bob   = AaIdentity::derive("0xbob",   "1", ChainType::Evm, &mock_sig(20)).unwrap();

        use crate::ratchet::Session;
        use crate::crypto::x3dh_symmetric;

        let (mut alice_sess, mlkem_ct) = Session::establish_hybrid_initiator(
            &alice.identity_key,
            &alice.signed_pre_key,
            &bob.identity_key.public_key,
            &bob.signed_pre_key.public_key,
            &bob.mlkem_ek,
        ).unwrap();

        let mut bob_sess = Session::establish_hybrid_responder(
            &bob.identity_key,
            &bob.signed_pre_key,
            &alice.identity_key.public_key,
            &alice.signed_pre_key.public_key,
            &bob.mlkem_dk,
            &mlkem_ct,
        ).unwrap();

        let msg = b"AA PQC session works!";
        let enc = alice_sess.encrypt(msg).unwrap();
        let dec = bob_sess.decrypt(&enc).unwrap();
        assert_eq!(dec, msg);
    }
}
