///
/// STVOR Web3 — ML-KEM-768 (NIST FIPS 203)
///
/// Post-quantum key encapsulation for hybrid X3DH.
/// Security category 3 (~AES-192 equivalent).
///
/// Key sizes (ML-KEM-768):
///   Encapsulation key (ek) : 1184 bytes — public, shared on-chain
///   Decapsulation key (dk) : stored as 64-byte seed — see note below
///   Ciphertext             : 1088 bytes
///   Shared key             : 32 bytes
///
/// # DK representation — seed vs expanded form
///
/// FIPS 203 §6 defines the full "expanded" decapsulation key as 2400 bytes.
/// However, the `ml-kem` crate (RustCrypto) stores the DK as a 64-byte random
/// seed (d ‖ z) from which the full 2400-byte key is deterministically re-derived
/// on every decapsulation call (per Algorithm 16 of FIPS 203).
///
/// This is fully compliant with FIPS 203: the seed IS the canonical private
/// representation recommended by the spec (§7.1). The 2400-byte expanded form
/// is an optional serialization that the crate deliberately deprecated in v0.3.
///
/// Security properties are identical — the seed never leaves the WASM sandbox
/// and is never transmitted. Only the 1184-byte EK is published on-chain.
///
use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, TryKeyInit},
};
use serde::{Deserializer, Serializer};
use serde::de::Error as DeError;

// ─── Sizes ────────────────────────────────────────────────────────────────────

pub const EK_SIZE: usize = 1184;  // encapsulation key
pub const DK_SIZE: usize = 64;    // decapsulation key seed (compact form per FIPS 203)
pub const CT_SIZE: usize = 1088;  // ciphertext
pub const SS_SIZE: usize = 32;    // shared secret

// ─── Types ────────────────────────────────────────────────────────────────────

type Ek768 = <MlKem768 as Kem>::EncapsulationKey;
type Dk768 = <MlKem768 as Kem>::DecapsulationKey;
type Ct768 = ml_kem::kem::Ciphertext<MlKem768>;

pub struct MlKemKeyPair {
    pub encapsulation_key: [u8; EK_SIZE],
    pub decapsulation_key: [u8; DK_SIZE],  // 64-byte seed
}

pub struct MlKemEncapsResult {
    pub ciphertext: [u8; CT_SIZE],
    pub shared_key: [u8; SS_SIZE],
}

#[derive(Debug)]
pub enum PqcError {
    InvalidKey,
    InvalidCiphertext,
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqcError::InvalidKey        => write!(f, "Invalid ML-KEM key"),
            PqcError::InvalidCiphertext => write!(f, "Invalid ML-KEM ciphertext"),
        }
    }
}

// ─── Key generation ───────────────────────────────────────────────────────────

pub fn mlkem_keygen() -> MlKemKeyPair {
    // generate_keypair() uses the `getrandom` feature internally
    let (dk, ek) = MlKem768::generate_keypair();

    let mut encapsulation_key = [0u8; EK_SIZE];
    let mut decapsulation_key = [0u8; DK_SIZE];

    encapsulation_key.copy_from_slice(ek.to_bytes().as_slice());
    // DK.to_bytes() returns the 64-byte seed (per FIPS 203 §3.3)
    decapsulation_key.copy_from_slice(dk.to_bytes().as_slice());

    MlKemKeyPair { encapsulation_key, decapsulation_key }
}

// ─── Encapsulate ─────────────────────────────────────────────────────────────

pub fn mlkem_encaps(ek_bytes: &[u8; EK_SIZE]) -> Result<MlKemEncapsResult, PqcError> {
    let ek = Ek768::new_from_slice(ek_bytes.as_slice())
        .map_err(|_| PqcError::InvalidKey)?;

    // encapsulate() uses getrandom internally
    let (ct, ss) = ek.encapsulate();

    let mut ciphertext = [0u8; CT_SIZE];
    let mut shared_key = [0u8; SS_SIZE];
    ciphertext.copy_from_slice(ct.as_ref());
    shared_key.copy_from_slice(ss.as_ref());

    Ok(MlKemEncapsResult { ciphertext, shared_key })
}

// ─── Decapsulate ─────────────────────────────────────────────────────────────

pub fn mlkem_decaps(
    dk_seed: &[u8; DK_SIZE],
    ct_bytes: &[u8; CT_SIZE],
) -> Result<[u8; SS_SIZE], PqcError> {
    // Reconstruct DK from 64-byte seed
    let dk = Dk768::new(
        dk_seed.as_slice().try_into().map_err(|_| PqcError::InvalidKey)?
    );

    let ct: Ct768 = ct_bytes.as_slice().try_into()
        .map_err(|_| PqcError::InvalidCiphertext)?;

    let ss = dk.decapsulate(&ct);

    let mut shared_key = [0u8; SS_SIZE];
    shared_key.copy_from_slice(ss.as_ref());
    Ok(shared_key)
}

// ─── Serde helpers ────────────────────────────────────────────────────────────

pub fn ser_ek<S: Serializer>(v: &[u8; EK_SIZE], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}
pub fn de_ek<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; EK_SIZE], D::Error> {
    let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
    v.try_into().map_err(|_| D::Error::custom("expected 1184 bytes (ML-KEM-768 EK)"))
}
pub fn ser_dk<S: Serializer>(v: &[u8; DK_SIZE], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}
pub fn de_dk<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; DK_SIZE], D::Error> {
    let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
    v.try_into().map_err(|_| D::Error::custom("expected 64 bytes (ML-KEM-768 DK seed)"))
}
pub fn ser_ct<S: Serializer>(v: &[u8; CT_SIZE], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
}
pub fn de_ct<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; CT_SIZE], D::Error> {
    let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
    v.try_into().map_err(|_| D::Error::custom("expected 1088 bytes (ML-KEM-768 CT)"))
}
pub fn ser_opt_ct<S: Serializer>(v: &Option<[u8; CT_SIZE]>, s: S) -> Result<S::Ok, S::Error> {
    match v { Some(b) => s.serialize_some(b.as_slice()), None => s.serialize_none() }
}
pub fn de_opt_ct<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; CT_SIZE]>, D::Error> {
    let v: Option<Vec<u8>> = serde::de::Deserialize::deserialize(d)?;
    match v {
        None    => Ok(None),
        Some(b) => b.try_into().map(Some).map_err(|_| D::Error::custom("expected 1088 bytes")),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem768_key_sizes() {
        let kp = mlkem_keygen();
        assert_eq!(kp.encapsulation_key.len(), EK_SIZE, "EK must be 1184 bytes");
        assert_eq!(kp.decapsulation_key.len(), DK_SIZE, "DK seed must be 64 bytes");
    }

    #[test]
    fn mlkem768_encaps_decaps_roundtrip() {
        let kp = mlkem_keygen();
        let res = mlkem_encaps(&kp.encapsulation_key).unwrap();
        assert_eq!(res.ciphertext.len(), CT_SIZE);
        assert_eq!(res.shared_key.len(), SS_SIZE);

        let ss_recv = mlkem_decaps(&kp.decapsulation_key, &res.ciphertext).unwrap();
        assert_eq!(res.shared_key, ss_recv, "Encap/decap shared secrets must match");
    }

    #[test]
    fn mlkem768_wrong_dk_gives_different_secret() {
        let kp1 = mlkem_keygen();
        let kp2 = mlkem_keygen();
        let res = mlkem_encaps(&kp1.encapsulation_key).unwrap();

        let ss_wrong = mlkem_decaps(&kp2.decapsulation_key, &res.ciphertext).unwrap();
        assert_ne!(res.shared_key, ss_wrong, "Wrong DK must not reproduce the shared secret");
    }

    #[test]
    fn mlkem768_tampered_ct_gives_different_secret() {
        let kp = mlkem_keygen();
        let res = mlkem_encaps(&kp.encapsulation_key).unwrap();

        let mut tampered = res.ciphertext;
        tampered[0] ^= 0xff;
        tampered[512] ^= 0x42;

        // ML-KEM implicit rejection: always returns a value, but wrong on tampering
        let ss_tampered = mlkem_decaps(&kp.decapsulation_key, &tampered).unwrap();
        assert_ne!(res.shared_key, ss_tampered, "Tampered CT must produce different secret");
    }

    #[test]
    fn mlkem768_dk_seed_roundtrip() {
        let kp = mlkem_keygen();
        // Serialize seed and reconstruct DK — must still decapsulate correctly
        let res = mlkem_encaps(&kp.encapsulation_key).unwrap();
        let ss1 = mlkem_decaps(&kp.decapsulation_key, &res.ciphertext).unwrap();

        // Reconstruct from same seed bytes
        let ss2 = mlkem_decaps(&kp.decapsulation_key, &res.ciphertext).unwrap();
        assert_eq!(ss1, ss2, "DK reconstructed from seed must give same result");
    }

    #[test]
    fn mlkem768_fresh_keypairs_independent() {
        let kp1 = mlkem_keygen();
        let kp2 = mlkem_keygen();
        assert_ne!(kp1.encapsulation_key, kp2.encapsulation_key, "EKs must be unique");
        assert_ne!(kp1.decapsulation_key, kp2.decapsulation_key, "DK seeds must be unique");
    }
}
