///
/// STVOR Web3 — WASM bindings
///
/// Exposes crypto-core to JavaScript/TypeScript via wasm-bindgen.
///
use wasm_bindgen::prelude::*;
use crate::crypto::{KeyPair, x3dh_symmetric, ec_sign, ec_verify, hkdf_sha256,
                    hybrid_x3dh_initiate, hybrid_x3dh_respond};
use crate::pqc::{mlkem_keygen, mlkem_encaps, mlkem_decaps, EK_SIZE, DK_SIZE, CT_SIZE};
use crate::ratchet::Session;
use crate::aa::{AaIdentity, ChainType, UserOpBinding, TonV5Extension, UserOperation};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn b64d(s: &str) -> Result<Vec<u8>, JsValue> {
    URL_SAFE_NO_PAD.decode(s).map_err(to_js_err)
}

fn b64e(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

// ─── Key pair ─────────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct WasmKeyPair {
    inner: KeyPair,
}

#[wasm_bindgen]
impl WasmKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmKeyPair {
        WasmKeyPair { inner: KeyPair::generate() }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        b64e(&self.inner.public_key)
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> String {
        b64e(&self.inner.private_key)
    }

    pub fn from_private_key(priv_b64: &str) -> Result<WasmKeyPair, JsValue> {
        let priv_bytes: [u8; 32] = b64d(priv_b64)?
            .try_into()
            .map_err(|_| to_js_err("Private key must be 32 bytes"))?;
        let kp = KeyPair::from_bytes(&priv_bytes).map_err(to_js_err)?;
        Ok(WasmKeyPair { inner: kp })
    }
}

// ─── Session ──────────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    /// Establish an E2EE session from wallet identity.
    /// my_ik, my_spk: WasmKeyPair
    /// peer_ik_b64, peer_spk_b64: base64url-encoded 65-byte public keys
    pub fn establish(
        my_ik: &WasmKeyPair,
        my_spk: &WasmKeyPair,
        peer_ik_b64: &str,
        peer_spk_b64: &str,
    ) -> Result<WasmSession, JsValue> {
        let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
            .try_into()
            .map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
        let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
            .try_into()
            .map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;

        let sk = x3dh_symmetric(&my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk)
            .map_err(to_js_err)?;

        Ok(WasmSession {
            inner: Session::establish(&my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk, sk),
        })
    }

    /// Encrypt plaintext bytes → base64url-encoded ciphertext+header blob
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<String, JsValue> {
        let blob = self.inner.encrypt(plaintext).map_err(to_js_err)?;
        Ok(b64e(&blob))
    }

    /// Decrypt base64url-encoded blob → plaintext bytes
    pub fn decrypt(&mut self, blob_b64: &str) -> Result<Vec<u8>, JsValue> {
        let blob = b64d(blob_b64)?;
        self.inner.decrypt(&blob).map_err(to_js_err)
    }

    /// Serialize session state to JSON string
    pub fn to_json(&self) -> Result<String, JsValue> {
        self.inner.to_json().map_err(to_js_err)
    }

    /// Restore session from JSON string
    pub fn from_json(json: &str) -> Result<WasmSession, JsValue> {
        let inner = Session::from_json(json).map_err(to_js_err)?;
        Ok(WasmSession { inner })
    }
}

// ─── Standalone crypto functions ──────────────────────────────────────────────

/// ECDSA sign: returns base64url DER signature
#[wasm_bindgen]
pub fn wasm_ec_sign(data: &[u8], key_pair: &WasmKeyPair) -> Result<String, JsValue> {
    let sig = ec_sign(data, &key_pair.inner).map_err(to_js_err)?;
    Ok(b64e(&sig))
}

/// ECDSA verify: public_key_b64 is base64url 65-byte uncompressed P-256
#[wasm_bindgen]
pub fn wasm_ec_verify(data: &[u8], sig_b64: &str, public_key_b64: &str) -> Result<bool, JsValue> {
    let sig = b64d(sig_b64)?;
    let pub_key: [u8; 65] = b64d(public_key_b64)?
        .try_into()
        .map_err(|_| to_js_err("public_key must be 65 bytes"))?;
    ec_verify(data, &sig, &pub_key).map_err(to_js_err)
}

/// HKDF-SHA256
#[wasm_bindgen]
pub fn wasm_hkdf(ikm_b64: &str, salt_b64: &str, info: &str, len: usize) -> Result<String, JsValue> {
    let ikm = b64d(ikm_b64)?;
    let salt = b64d(salt_b64)?;
    let out = hkdf_sha256(&ikm, &salt, info.as_bytes(), len);
    Ok(b64e(&out))
}

/// X3DH shared key derivation (classical)
#[wasm_bindgen]
pub fn wasm_x3dh(
    my_ik: &WasmKeyPair,
    my_spk: &WasmKeyPair,
    peer_ik_b64: &str,
    peer_spk_b64: &str,
) -> Result<String, JsValue> {
    let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
        .try_into()
        .map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
    let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
        .try_into()
        .map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
    let sk = x3dh_symmetric(&my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk)
        .map_err(to_js_err)?;
    Ok(b64e(&sk))
}

// ─── ML-KEM-768 WASM bindings ─────────────────────────────────────────────────

/// ML-KEM-768 key generation (NIST FIPS 203).
///
/// Returns JSON: { ek: base64url, dk: base64url }
///
/// - ek: 1184-byte encapsulation key (public) — publish on-chain / in registry
/// - dk: 64-byte seed (private) — this is d‖z per FIPS 203 §7.1, NOT the
///   2400-byte expanded form. The full expanded DK is re-derived from this seed
///   on every decapsulation call (Algorithm 16). This is the canonical private
///   representation recommended by FIPS 203. Keep dk secret, never transmit it.
#[wasm_bindgen]
pub fn wasm_mlkem_keygen() -> Result<String, JsValue> {
    let kp = mlkem_keygen();
    Ok(format!(
        r#"{{"ek":"{}","dk":"{}"}}"#,
        b64e(&kp.encapsulation_key),
        b64e(&kp.decapsulation_key),
    ))
}

/// ML-KEM-768 encapsulate. Returns JSON: { ct: base64url, ss: base64url }
#[wasm_bindgen]
pub fn wasm_mlkem_encaps(ek_b64: &str) -> Result<String, JsValue> {
    let ek: [u8; EK_SIZE] = b64d(ek_b64)?
        .try_into()
        .map_err(|_| to_js_err(format!("EK must be {} bytes", EK_SIZE)))?;
    let res = mlkem_encaps(&ek).map_err(to_js_err)?;
    Ok(format!(
        r#"{{"ct":"{}","ss":"{}"}}"#,
        b64e(&res.ciphertext),
        b64e(&res.shared_key),
    ))
}

/// ML-KEM-768 decapsulate. Returns base64url-encoded 32-byte shared secret.
#[wasm_bindgen]
pub fn wasm_mlkem_decaps(dk_b64: &str, ct_b64: &str) -> Result<String, JsValue> {
    let dk: [u8; DK_SIZE] = b64d(dk_b64)?
        .try_into()
        .map_err(|_| to_js_err(format!("DK seed must be {} bytes", DK_SIZE)))?;
    let ct: [u8; CT_SIZE] = b64d(ct_b64)?
        .try_into()
        .map_err(|_| to_js_err(format!("CT must be {} bytes", CT_SIZE)))?;
    let ss = mlkem_decaps(&dk, &ct).map_err(to_js_err)?;
    Ok(b64e(&ss))
}

// ─── Hybrid X3DH + ML-KEM-768 WASM bindings ──────────────────────────────────

/// Hybrid X3DH initiator: returns JSON { shared_key: base64url, mlkem_ct: base64url }
/// Send mlkem_ct to the responder in the handshake payload.
#[wasm_bindgen]
pub fn wasm_hybrid_initiate(
    my_ik: &WasmKeyPair,
    my_spk: &WasmKeyPair,
    peer_ik_b64: &str,
    peer_spk_b64: &str,
    peer_mlkem_ek_b64: &str,
) -> Result<String, JsValue> {
    let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
        .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
    let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
        .try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
    let peer_ek: [u8; EK_SIZE] = b64d(peer_mlkem_ek_b64)?
        .try_into().map_err(|_| to_js_err(format!("peer_mlkem_ek must be {} bytes", EK_SIZE)))?;

    let res = hybrid_x3dh_initiate(&my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk, &peer_ek)
        .map_err(to_js_err)?;

    Ok(format!(
        r#"{{"shared_key":"{}","mlkem_ct":"{}"}}"#,
        b64e(&res.shared_key),
        b64e(&res.mlkem_ct),
    ))
}

/// Hybrid X3DH responder: returns base64url-encoded 32-byte shared key.
#[wasm_bindgen]
pub fn wasm_hybrid_respond(
    my_ik: &WasmKeyPair,
    my_spk: &WasmKeyPair,
    peer_ik_b64: &str,
    peer_spk_b64: &str,
    my_mlkem_dk_b64: &str,
    mlkem_ct_b64: &str,
) -> Result<String, JsValue> {
    let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
        .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
    let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
        .try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
    let my_dk: [u8; DK_SIZE] = b64d(my_mlkem_dk_b64)?
        .try_into().map_err(|_| to_js_err(format!("DK seed must be {} bytes", DK_SIZE)))?;
    let ct: [u8; CT_SIZE] = b64d(mlkem_ct_b64)?
        .try_into().map_err(|_| to_js_err(format!("CT must be {} bytes", CT_SIZE)))?;

    let sk = hybrid_x3dh_respond(&my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk, &my_dk, &ct)
        .map_err(to_js_err)?;

    Ok(b64e(&sk))
}

/// Hybrid session establish — initiator side.
/// Returns JSON: { session_json: string, mlkem_ct: base64url }
#[wasm_bindgen]
pub fn wasm_hybrid_session_initiate(
    my_ik: &WasmKeyPair,
    my_spk: &WasmKeyPair,
    peer_ik_b64: &str,
    peer_spk_b64: &str,
    peer_mlkem_ek_b64: &str,
) -> Result<String, JsValue> {
    let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
        .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
    let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
        .try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
    let peer_ek: [u8; EK_SIZE] = b64d(peer_mlkem_ek_b64)?
        .try_into().map_err(|_| to_js_err(format!("peer_mlkem_ek must be {} bytes", EK_SIZE)))?;

    let (session, ct) = Session::establish_hybrid_initiator(
        &my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk, &peer_ek,
    ).map_err(to_js_err)?;

    let session_json = session.to_json().map_err(to_js_err)?;
    let session_json_escaped = session_json.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        r#"{{"session_json":"{}","mlkem_ct":"{}"}}"#,
        session_json_escaped,
        b64e(&ct),
    ))
}

/// Hybrid session establish — responder side. Returns WasmSession.
#[wasm_bindgen]
pub fn wasm_hybrid_session_respond(
    my_ik: &WasmKeyPair,
    my_spk: &WasmKeyPair,
    peer_ik_b64: &str,
    peer_spk_b64: &str,
    my_mlkem_dk_b64: &str,
    mlkem_ct_b64: &str,
) -> Result<WasmSession, JsValue> {
    let peer_ik: [u8; 65] = b64d(peer_ik_b64)?
        .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
    let peer_spk: [u8; 65] = b64d(peer_spk_b64)?
        .try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
    let my_dk: [u8; DK_SIZE] = b64d(my_mlkem_dk_b64)?
        .try_into().map_err(|_| to_js_err(format!("DK seed must be {} bytes", DK_SIZE)))?;
    let ct: [u8; CT_SIZE] = b64d(mlkem_ct_b64)?
        .try_into().map_err(|_| to_js_err(format!("CT must be {} bytes", CT_SIZE)))?;

    let inner = Session::establish_hybrid_responder(
        &my_ik.inner, &my_spk.inner, &peer_ik, &peer_spk, &my_dk, &ct,
    ).map_err(to_js_err)?;

    Ok(WasmSession { inner })
}

// ─── Account Abstraction WASM bindings ───────────────────────────────────────

/// AA identity container exposed to JS
#[wasm_bindgen]
pub struct WasmAaIdentity {
    inner: AaIdentity,
}

#[wasm_bindgen]
impl WasmAaIdentity {
    /// Derive AA identity from a wallet signature.
    ///
    /// chain_type: "evm" | "ton"
    /// Returns WasmAaIdentity with all keys derived.
    pub fn derive(
        address: &str,
        chain_id: &str,
        chain_type: &str,
        signature_b64: &str,
    ) -> Result<WasmAaIdentity, JsValue> {
        let sig = b64d(signature_b64)?;
        let ct  = match chain_type.to_lowercase().as_str() {
            "ton" => ChainType::Ton,
            _     => ChainType::Evm,
        };
        let inner = AaIdentity::derive(address, chain_id, ct, &sig)
            .map_err(to_js_err)?;
        Ok(WasmAaIdentity { inner })
    }

    /// P-256 identity public key (base64url, 65 bytes)
    #[wasm_bindgen(getter)]
    pub fn identity_key(&self) -> String {
        b64e(&self.inner.identity_key.public_key)
    }

    /// P-256 signed pre-key public (base64url, 65 bytes)
    #[wasm_bindgen(getter)]
    pub fn signed_pre_key(&self) -> String {
        b64e(&self.inner.signed_pre_key.public_key)
    }

    /// ECDSA signature of SPK by IK (base64url, DER)
    #[wasm_bindgen(getter)]
    pub fn spk_signature(&self) -> String {
        b64e(&self.inner.spk_signature)
    }

    /// ML-KEM-768 encapsulation key (base64url, 1184 bytes)
    #[wasm_bindgen(getter)]
    pub fn mlkem_ek(&self) -> String {
        b64e(&self.inner.mlkem_ek)
    }

    /// Wallet address
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address.clone()
    }

    /// Chain type: "evm" or "ton"
    #[wasm_bindgen(getter)]
    pub fn chain_type(&self) -> String {
        match self.inner.chain_type {
            ChainType::Evm => "evm".to_string(),
            ChainType::Ton => "ton".to_string(),
        }
    }

    /// Verify the SPK signature — returns true if valid
    pub fn verify_spk(&self) -> Result<bool, JsValue> {
        self.inner.verify_spk().map_err(to_js_err)
    }

    /// Establish hybrid X3DH session from this AA identity.
    /// Returns JSON: { session_json, mlkem_ct }
    pub fn establish_session_with(
        &self,
        peer_ik_b64:    &str,
        peer_spk_b64:   &str,
        peer_mlkem_ek_b64: &str,
    ) -> Result<String, JsValue> {
        let peer_ik:  [u8; 65]    = b64d(peer_ik_b64)?  .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
        let peer_spk: [u8; 65]    = b64d(peer_spk_b64)? .try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
        let peer_ek:  [u8; EK_SIZE] = b64d(peer_mlkem_ek_b64)?.try_into().map_err(|_| to_js_err("peer_mlkem_ek must be 1184 bytes"))?;

        let (session, ct) = Session::establish_hybrid_initiator(
            &self.inner.identity_key,
            &self.inner.signed_pre_key,
            &peer_ik, &peer_spk, &peer_ek,
        ).map_err(to_js_err)?;

        let session_json = session.to_json().map_err(to_js_err)?;
        let session_escaped = session_json.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!(r#"{{"session_json":"{}","mlkem_ct":"{}"}}"#, session_escaped, b64e(&ct)))
    }

    /// Respond to a hybrid X3DH session from a peer.
    /// Returns WasmSession ready to use.
    pub fn respond_to_session(
        &self,
        peer_ik_b64:  &str,
        peer_spk_b64: &str,
        mlkem_ct_b64: &str,
    ) -> Result<WasmSession, JsValue> {
        let peer_ik:  [u8; 65]    = b64d(peer_ik_b64)? .try_into().map_err(|_| to_js_err("peer_ik must be 65 bytes"))?;
        let peer_spk: [u8; 65]    = b64d(peer_spk_b64)?.try_into().map_err(|_| to_js_err("peer_spk must be 65 bytes"))?;
        let ct:       [u8; CT_SIZE] = b64d(mlkem_ct_b64)?.try_into().map_err(|_| to_js_err("CT must be 1088 bytes"))?;

        let inner = Session::establish_hybrid_responder(
            &self.inner.identity_key,
            &self.inner.signed_pre_key,
            &peer_ik, &peer_spk,
            &self.inner.mlkem_dk,
            &ct,
        ).map_err(to_js_err)?;

        Ok(WasmSession { inner })
    }
}

/// Derive AA identity — shorthand function (no class needed)
/// Returns JSON: { ik, spk, spk_sig, mlkem_ek, address, chain_type }
#[wasm_bindgen]
pub fn wasm_aa_derive(
    address:       &str,
    chain_id:      &str,
    chain_type:    &str,
    signature_b64: &str,
) -> Result<String, JsValue> {
    let id = WasmAaIdentity::derive(address, chain_id, chain_type, signature_b64)?;
    Ok(format!(
        r#"{{"ik":"{}","spk":"{}","spk_sig":"{}","mlkem_ek":"{}","address":"{}","chain_type":"{}"}}"#,
        id.identity_key(), id.signed_pre_key(), id.spk_signature(),
        id.mlkem_ek(), id.address(), id.chain_type()
    ))
}

/// Create a UserOperation binding — proves E2EE session belongs to this AA op.
/// Returns JSON: { user_op_hash, identity_sig, session_commitment }
#[wasm_bindgen]
pub fn wasm_aa_bind_userop(
    user_op_hash_hex: &str,
    identity:         &WasmAaIdentity,
    session_root_b64: &str,
) -> Result<String, JsValue> {
    let hash: [u8; 32] = hex_to_bytes32(user_op_hash_hex)?;
    let skey: [u8; 32] = b64d(session_root_b64)?
        .try_into().map_err(|_| to_js_err("session_root must be 32 bytes"))?;

    let binding = UserOpBinding::create(&hash, &identity.inner, &skey)
        .map_err(to_js_err)?;

    Ok(serde_json::to_string(&binding).map_err(to_js_err)?)
}

/// Verify a UserOperation binding.
#[wasm_bindgen]
pub fn wasm_aa_verify_userop(
    binding_json:     &str,
    identity_ik_b64:  &str,
    session_root_b64: &str,
) -> Result<bool, JsValue> {
    let binding: UserOpBinding = serde_json::from_str(binding_json)
        .map_err(to_js_err)?;
    let ik:   [u8; 65] = b64d(identity_ik_b64)?
        .try_into().map_err(|_| to_js_err("identity_ik must be 65 bytes"))?;
    let skey: [u8; 32] = b64d(session_root_b64)?
        .try_into().map_err(|_| to_js_err("session_root must be 32 bytes"))?;

    binding.verify(&ik, &skey).map_err(to_js_err)
}

/// Sign a TON v5 extension body with AA identity.
/// Returns JSON: { body_hex, identity_sig, wallet_address }
#[wasm_bindgen]
pub fn wasm_aa_sign_ton_extension(
    wallet_address: &str,
    body_hex:       &str,
    identity:       &WasmAaIdentity,
) -> Result<String, JsValue> {
    let ext = TonV5Extension::create(wallet_address, body_hex, &identity.inner)
        .map_err(to_js_err)?;
    Ok(serde_json::to_string(&ext).map_err(to_js_err)?)
}

/// Verify a TON v5 extension signature.
#[wasm_bindgen]
pub fn wasm_aa_verify_ton_extension(
    ext_json:        &str,
    identity_ik_b64: &str,
) -> Result<bool, JsValue> {
    let ext: TonV5Extension = serde_json::from_str(ext_json).map_err(to_js_err)?;
    let ik: [u8; 65] = b64d(identity_ik_b64)?
        .try_into().map_err(|_| to_js_err("identity_ik must be 65 bytes"))?;
    ext.verify(&ik).map_err(to_js_err)
}

// ─── Helper: hex → [u8;32] ────────────────────────────────────────────────────

fn hex_to_bytes32(s: &str) -> Result<[u8; 32], JsValue> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(to_js_err(format!("Expected 64 hex chars, got {}", s.len())));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).map_err(to_js_err)?, 16)
            .map_err(to_js_err)?;
    }
    Ok(out)
}
