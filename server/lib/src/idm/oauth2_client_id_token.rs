//! Kubidm: verification of the OpenID Connect `id_token` that an upstream identity
//! provider (an `OAuth2Federation`) returns from its token endpoint.
//!
//! The JWKS is fetched (and cached) by the caller, see [AuthExternal::OAuth2JwksRequest].
//! This module only verifies a token against the keys it is given and checks its claims
//! against the auth session, so it is deterministic and does no I/O.
//!
//! Only `RS256` and `ES256` are accepted. `none`, `PS256`, `EdDSA` and other algorithms
//! are not parsed by `compact_jwt`, and `HS256` (a shared secret, never published in a
//! JWKS) is rejected explicitly. Keys and algorithms embedded in the token header (`jwk`,
//! `jku`, `x5c`) are never trusted: the key always comes from the configured JWKS.
//!
//! [AuthExternal::OAuth2JwksRequest]: crate::idm::authentication::AuthExternal::OAuth2JwksRequest

use crate::prelude::*;
use compact_jwt::{
    crypto::JwsRs256Verifier, JwaAlg, Jwk, JwkUse, Jws, JwsCompact, JwsEs256Verifier, JwsVerifier,
};
use kubidm_proto::oauth2_federation::OAuth2ClientIdTokenClaims;
use std::str::FromStr;

/// Allowed clock difference with the IdP for `exp`, `iat` and `nbf`.
pub(crate) const ID_TOKEN_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The smallest accepted RSA modulus, in bits.
const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Why an id_token was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdTokenError {
    /// No key of the JWKS can verify the token: its `kid` is unknown, or no key matches
    /// its algorithm. A refreshed JWKS may have the key.
    UnknownKey,
    /// A matching key was found but the signature is invalid.
    Signature,
    /// The token is valid but one of its claims is not acceptable.
    Claims(&'static str),
    /// The token is valid but for a different subject than the linked account.
    Subject,
}

/// What the auth session expects from the id_token.
pub(crate) struct IdTokenExpectations<'a> {
    pub(crate) issuer: &'a Url,
    pub(crate) client_id: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) subject: &'a str,
}

/// Parse an id_token, and reject it unless it is signed with an allowed algorithm.
pub(crate) fn parse_id_token(id_token: &str) -> Result<JwsCompact, &'static str> {
    let id_token = JwsCompact::from_str(id_token).map_err(|err| {
        debug!(?err, "invalid id_token");
        "is not a valid compact JWS, or uses an algorithm that is not allowed"
    })?;

    match id_token.header().alg {
        JwaAlg::RS256 | JwaAlg::ES256 => Ok(id_token),
        JwaAlg::HS256 => Err("uses the HS256 algorithm, which is not allowed"),
    }
}

/// Verify the signature of `id_token` with one of `keys`, then check its claims.
pub(crate) fn verify_id_token(
    id_token: &JwsCompact,
    keys: &[Jwk],
    expect: &IdTokenExpectations<'_>,
    current_time: Duration,
) -> Result<OAuth2ClientIdTokenClaims, IdTokenError> {
    let verified = verify_signature(id_token, keys)?;

    let claims: OAuth2ClientIdTokenClaims = verified.from_json().map_err(|err| {
        debug!(?err, "invalid id_token claims");
        IdTokenError::Claims("has invalid claims")
    })?;

    check_claims(&claims, expect, current_time)?;
    Ok(claims)
}

fn verify_signature(id_token: &JwsCompact, keys: &[Jwk]) -> Result<Jws, IdTokenError> {
    let header = id_token.header();
    let alg = header.alg;
    let kid = header.kid.as_deref();

    let mut key_found = false;
    for key in keys.iter().filter(|key| key_matches(key, alg, kid)) {
        key_found = true;
        let result = match alg {
            JwaAlg::RS256 => {
                JwsRs256Verifier::try_from(key).and_then(|verifier| verifier.verify(id_token))
            }
            JwaAlg::ES256 => {
                JwsEs256Verifier::try_from(key).and_then(|verifier| verifier.verify(id_token))
            }
            // Never matched by `key_matches`, rejected by `parse_id_token` already.
            JwaAlg::HS256 => return Err(IdTokenError::Signature),
        };
        match result {
            Ok(verified) => return Ok(verified),
            Err(err) => debug!(?err, ?kid, "id_token signature not verified by key"),
        }
    }

    if key_found {
        Err(IdTokenError::Signature)
    } else {
        Err(IdTokenError::UnknownKey)
    }
}

/// Can `key` verify a token signed with `alg` by the key `kid`. A key restricted to
/// another algorithm or to encryption is never used, and neither is an RSA key smaller
/// than 2048 bits. When the token names its key, only a key with that `kid` is used.
fn key_matches(key: &Jwk, alg: JwaAlg, kid: Option<&str>) -> bool {
    let (key_alg, key_use, key_kid, kind_matches) = match key {
        Jwk::EC {
            alg: key_alg,
            use_,
            kid,
            ..
        } => (key_alg, use_, kid, alg == JwaAlg::ES256),
        Jwk::RSA {
            n,
            alg: key_alg,
            use_,
            kid,
            ..
        } => (
            key_alg,
            use_,
            kid,
            alg == JwaAlg::RS256 && bit_length(n) >= MIN_RSA_MODULUS_BITS,
        ),
    };

    kind_matches
        && key_alg.is_none_or(|key_alg| key_alg == alg)
        && *key_use != Some(JwkUse::Enc)
        && kid.is_none_or(|kid| key_kid.as_deref() == Some(kid))
}

/// The bit length of the big endian unsigned integer `n` (leading zero bytes allowed).
fn bit_length(n: &[u8]) -> usize {
    let mut digits = n.iter().skip_while(|byte| **byte == 0);
    match digits.next() {
        Some(first) => (8 - first.leading_zeros() as usize) + 8 * digits.count(),
        None => 0,
    }
}

/// `value` without one trailing `/`, if it has one. Only one is removed, so that
/// `https://idp/realms/main//` is not mistaken for `https://idp/realms/main`.
fn strip_one_slash(value: &str) -> &str {
    value.strip_suffix('/').unwrap_or(value)
}

/// Check the claims of a verified id_token, per OpenID Connect Core 1.0 section 3.1.3.7.
fn check_claims(
    claims: &OAuth2ClientIdTokenClaims,
    expect: &IdTokenExpectations<'_>,
    current_time: Duration,
) -> Result<(), IdTokenError> {
    let iss = claims
        .iss
        .as_deref()
        .ok_or(IdTokenError::Claims("has no issuer"))?;
    if strip_one_slash(iss) != strip_one_slash(expect.issuer.as_str()) {
        return Err(IdTokenError::Claims("was issued by a different issuer"));
    }

    if !claims.aud.iter().any(|aud| aud == expect.client_id) {
        return Err(IdTokenError::Claims("is not intended for this client"));
    }
    // With several audiences, the authorised party must be named, and it must be us.
    if claims.aud.len() > 1 && claims.azp.is_none() {
        return Err(IdTokenError::Claims(
            "has several audiences but no authorised party",
        ));
    }
    if claims
        .azp
        .as_deref()
        .is_some_and(|azp| azp != expect.client_id)
    {
        return Err(IdTokenError::Claims(
            "was issued to a different authorised party",
        ));
    }

    let now = i64::try_from(current_time.as_secs()).unwrap_or(i64::MAX);
    let skew = i64::try_from(ID_TOKEN_CLOCK_SKEW.as_secs()).unwrap_or_default();

    let exp = claims.exp.ok_or(IdTokenError::Claims("has no expiry"))?;
    if exp.saturating_add(skew) <= now {
        return Err(IdTokenError::Claims("has expired"));
    }
    let iat = claims
        .iat
        .ok_or(IdTokenError::Claims("has no issued at time"))?;
    if iat > now.saturating_add(skew) {
        return Err(IdTokenError::Claims("was issued in the future"));
    }
    if claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(skew)) {
        return Err(IdTokenError::Claims("is not valid yet"));
    }

    if claims.nonce.as_deref() != Some(expect.nonce) {
        return Err(IdTokenError::Claims("has a different nonce"));
    }

    if claims.sub.as_deref() != Some(expect.subject) {
        return Err(IdTokenError::Subject);
    }

    Ok(())
}

/// Test helpers: an IdP that signs id_tokens with locally generated keys.
#[cfg(test)]
pub(crate) mod test_idp {
    use super::*;
    use compact_jwt::{
        crypto::JwsRs256Signer, jws::JwsBuilder, JwsEs256Signer, JwsHs256Signer, JwsSigner,
        JwsSignerToVerifier,
    };
    use serde_json::{json, Value};

    pub(crate) const ISSUER: &str = "https://idp.example.com/realms/main";
    pub(crate) const CLIENT_ID: &str = "kubidm";
    pub(crate) const NONCE: &str = "the-session-nonce";
    pub(crate) const SUBJECT: &str = "6b0f8f1e-1f43-4a0c-9c43-7b8f6d1c2a10";
    /// The time the id_token is validated at, in seconds since the epoch.
    pub(crate) const NOW: u64 = 1_800_000_000;

    pub(crate) enum Signer {
        Es256(JwsEs256Signer),
        Rs256(JwsRs256Signer),
        Hs256(JwsHs256Signer),
    }

    impl Signer {
        pub(crate) fn es256(kid: &str) -> Self {
            let mut signer = JwsEs256Signer::generate_es256().expect("failed to generate key");
            signer.set_kid(kid);
            Signer::Es256(signer)
        }

        pub(crate) fn rs256(kid: &str) -> Self {
            let mut signer = JwsRs256Signer::generate_rs256().expect("failed to generate key");
            signer.set_kid(kid);
            Signer::Rs256(signer)
        }

        pub(crate) fn hs256() -> Self {
            Signer::Hs256(JwsHs256Signer::generate_hs256().expect("failed to generate key"))
        }

        /// The public key, as the IdP publishes it in its JWKS.
        pub(crate) fn jwk(&self) -> Jwk {
            match self {
                // The verifier's JWK carries the kid set on the signer.
                Signer::Es256(signer) => signer
                    .get_verifier()
                    .and_then(|verifier| verifier.public_key_as_jwk()),
                Signer::Rs256(signer) => signer
                    .get_verifier()
                    .and_then(|verifier| verifier.public_key_as_jwk()),
                Signer::Hs256(_) => panic!("an HS256 key is never published"),
            }
            .expect("failed to export the public key")
        }

        /// Sign `claims` as a compact JWS, with `kid` in the header unless it is `None`.
        pub(crate) fn sign(&self, claims: &Value, kid: Option<&str>) -> String {
            let jws = JwsBuilder::into_json(claims)
                .expect("invalid claims")
                .set_kid(kid)
                .build();
            match self {
                Signer::Es256(signer) => signer
                    .set_sign_option_embed_kid(false)
                    .sign(&jws)
                    .map(|signed| signed.to_string()),
                Signer::Rs256(signer) => signer
                    .set_sign_option_embed_kid(false)
                    .sign(&jws)
                    .map(|signed| signed.to_string()),
                Signer::Hs256(signer) => signer
                    .set_sign_option_embed_kid(false)
                    .sign(&jws)
                    .map(|signed| signed.to_string()),
            }
            .expect("failed to sign")
        }

        /// Sign `claims` with this signer's own `kid`.
        pub(crate) fn sign_with_kid(&self, claims: &Value) -> String {
            let kid = match self {
                Signer::Es256(signer) => signer.get_kid().to_string(),
                Signer::Rs256(signer) => signer.get_kid().to_string(),
                Signer::Hs256(signer) => JwsSigner::get_kid(signer).to_string(),
            };
            self.sign(claims, Some(&kid))
        }
    }

    /// Valid id_token claims for [SUBJECT], [CLIENT_ID] and [NONCE] at [NOW].
    pub(crate) fn valid_claims() -> Value {
        json!({
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": CLIENT_ID,
            "exp": NOW + 300,
            "iat": NOW - 10,
            "nonce": NONCE,
            "email": "alice@example.com",
        })
    }

    /// `valid_claims()` with `changes` applied: a `null` value removes the claim.
    pub(crate) fn claims_with(changes: &Value) -> Value {
        let mut claims = valid_claims();
        let (Some(claims_map), Some(changes)) = (claims.as_object_mut(), changes.as_object())
        else {
            panic!("claims must be objects");
        };
        for (name, value) in changes {
            if value.is_null() {
                claims_map.remove(name);
            } else {
                claims_map.insert(name.clone(), value.clone());
            }
        }
        claims
    }
}

#[cfg(test)]
mod tests {
    use super::test_idp::*;
    use super::*;
    use serde_json::json;

    fn issuer() -> Url {
        Url::parse(ISSUER).expect("invalid issuer")
    }

    fn verify(id_token: &str, keys: &[Jwk]) -> Result<OAuth2ClientIdTokenClaims, IdTokenError> {
        verify_with_issuer(id_token, keys, &issuer())
    }

    fn verify_with_issuer(
        id_token: &str,
        keys: &[Jwk],
        issuer: &Url,
    ) -> Result<OAuth2ClientIdTokenClaims, IdTokenError> {
        let id_token = parse_id_token(id_token).map_err(IdTokenError::Claims)?;
        let expect = IdTokenExpectations {
            issuer,
            client_id: CLIENT_ID,
            nonce: NONCE,
            subject: SUBJECT,
        };
        verify_id_token(&id_token, keys, &expect, Duration::from_secs(NOW))
    }

    fn b64(value: &serde_json::Value) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    /// Sign `claims` under exactly `header` with a new ES256 key, bypassing compact_jwt's
    /// header handling. Returns the token and the public key, with `kid` "key".
    fn sign_raw_es256(header: &serde_json::Value, claims: &serde_json::Value) -> (String, Jwk) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use crypto_glue::{
            ecdsa_p256::{new_key, EcdsaP256Signature, EcdsaP256SigningKey},
            traits::Signer as _,
        };
        let skey = new_key();
        let input = format!("{}.{}", b64(header), b64(claims));
        let signature: EcdsaP256Signature = EcdsaP256SigningKey::from(&skey).sign(input.as_bytes());
        let token = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes().as_slice())
        );
        let mut jwk = JwsEs256Verifier::from(skey.public_key())
            .public_key_as_jwk()
            .expect("failed to export the public key");
        if let Jwk::EC { kid, .. } = &mut jwk {
            *kid = Some("key".to_string());
        }
        (token, jwk)
    }

    #[test]
    fn test_id_token_valid_es256_and_rs256() {
        for signer in [Signer::es256("ec-key"), Signer::rs256("rsa-key")] {
            let token = signer.sign_with_kid(&valid_claims());
            let claims = verify(&token, &[signer.jwk()]).expect("must be accepted");
            assert_eq!(claims.sub.as_deref(), Some(SUBJECT));
        }
    }

    /// A JWKS usually has several keys (and kinds): the one named by `kid` is used.
    #[test]
    fn test_id_token_key_selection() {
        let ec = Signer::es256("ec-key");
        let rsa = Signer::rs256("rsa-key");
        let other = Signer::es256("other-key");
        let keys = [other.jwk(), rsa.jwk(), ec.jwk()];

        verify(&ec.sign_with_kid(&valid_claims()), &keys).expect("ec key must be found");
        verify(&rsa.sign_with_kid(&valid_claims()), &keys).expect("rsa key must be found");

        // Without a kid, every key of the token's algorithm is tried.
        verify(&ec.sign(&valid_claims(), None), &keys).expect("ec key must be found");
        verify(&rsa.sign(&valid_claims(), None), &keys).expect("rsa key must be found");

        // Unknown kid: no key is tried, even though the right key is in the set.
        assert_eq!(
            verify(&ec.sign(&valid_claims(), Some("unknown")), &keys).map(|_| ()),
            Err(IdTokenError::UnknownKey)
        );
        // No key of the token's kind.
        assert_eq!(
            verify(&rsa.sign(&valid_claims(), None), &[ec.jwk()]).map(|_| ()),
            Err(IdTokenError::UnknownKey)
        );
        assert_eq!(
            verify(&ec.sign_with_kid(&valid_claims()), &[]).map(|_| ()),
            Err(IdTokenError::UnknownKey)
        );
    }

    /// A key with the right kid that did not sign the token, and a tampered payload.
    #[test]
    fn test_id_token_bad_signature() {
        let signer = Signer::es256("key");
        let impostor = Signer::es256("key");
        let token = impostor.sign_with_kid(&valid_claims());
        assert_eq!(
            verify(&token, &[signer.jwk()]).map(|_| ()),
            Err(IdTokenError::Signature)
        );

        // Same header and signature, payload for another subject.
        let token = signer.sign_with_kid(&valid_claims());
        let forged = signer.sign_with_kid(&claims_with(&json!({"sub": "attacker"})));
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_payload = forged.split('.').nth(1).expect("no payload");
        parts[1] = forged_payload;
        assert_eq!(
            verify(&parts.join("."), &[signer.jwk()]).map(|_| ()),
            Err(IdTokenError::Signature)
        );
    }

    /// Keys restricted to another algorithm or to encryption, or weak RSA keys, are
    /// never used.
    #[test]
    fn test_id_token_unusable_keys() {
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&valid_claims());

        let mut wrong_alg = signer.jwk();
        let mut enc = signer.jwk();
        if let (Jwk::EC { alg, .. }, Jwk::EC { use_, .. }) = (&mut wrong_alg, &mut enc) {
            *alg = Some(JwaAlg::RS256);
            *use_ = Some(JwkUse::Enc);
        }
        for key in [wrong_alg, enc] {
            assert_eq!(
                verify(&token, &[key]).map(|_| ()),
                Err(IdTokenError::UnknownKey)
            );
        }

        // A 2047 bit modulus (256 bytes, top bit clear) and a 2040 bit one are too small.
        let rsa = Signer::rs256("rsa");
        let token = rsa.sign_with_kid(&valid_claims());
        let mut bit_2047 = rsa.jwk();
        let mut byte_255 = rsa.jwk();
        if let (Jwk::RSA { n: n_2047, .. }, Jwk::RSA { n: n_255, .. }) =
            (&mut bit_2047, &mut byte_255)
        {
            assert_eq!(bit_length(n_2047), 2048);
            n_2047[0] = 0x7f;
            assert_eq!(bit_length(n_2047), 2047);
            n_255.remove(0);
        }
        for weak in [bit_2047, byte_255] {
            assert_eq!(
                verify(&token, &[weak]).map(|_| ()),
                Err(IdTokenError::UnknownKey)
            );
        }
    }

    #[test]
    fn test_id_token_bit_length() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[1]), 1);
        assert_eq!(bit_length(&[0x80]), 8);
        assert_eq!(bit_length(&[0, 0x01, 0x00]), 9);
        let mut n = vec![0xff; 256];
        assert_eq!(bit_length(&n), 2048);
        n[0] = 0x7f;
        assert_eq!(bit_length(&n), 2047);
        n[0] = 0x01;
        assert_eq!(bit_length(&n), 2041);
    }

    /// `none`, HS256 and algorithms that compact_jwt does not support are rejected
    /// before any key is looked up.
    #[test]
    fn test_id_token_alg_allow_list() {
        let hs = Signer::hs256().sign_with_kid(&valid_claims());
        assert!(parse_id_token(&hs).is_err());

        let payload = b64(&valid_claims());
        for alg in ["none", "None", "PS256", "EdDSA", "RS512", "ES384", ""] {
            let token = format!("{}.{payload}.", b64(&json!({"alg": alg, "kid": "key"})));
            assert!(
                parse_id_token(&token).is_err(),
                "alg {alg:?} must be rejected"
            );
        }
        assert!(parse_id_token(&format!("{}.{payload}.", b64(&json!({})))).is_err());
        assert!(parse_id_token("not-a-jwt").is_err());

        // An ES256 token re-labelled as RS256 does not verify with the EC key.
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&valid_claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[0] = b64(&json!({"alg": "RS256", "kid": "key"}));
        assert_eq!(
            verify(&parts.join("."), &[signer.jwk()]).map(|_| ()),
            Err(IdTokenError::UnknownKey)
        );
    }

    /// The header can not bring its own key.
    #[test]
    fn test_id_token_embedded_jwk_ignored() {
        let signer = Signer::es256("key");
        let attacker = match compact_jwt::JwsEs256Signer::generate_es256() {
            Ok(signer) => signer.set_sign_option_embed_jwk(true),
            Err(err) => panic!("{err:?}"),
        };
        let jws = compact_jwt::jws::JwsBuilder::into_json(&valid_claims())
            .expect("invalid claims")
            .set_kid(Some("key"))
            .build();
        let token = compact_jwt::JwsSigner::sign(&attacker, &jws)
            .expect("failed to sign")
            .to_string();
        assert_eq!(
            verify(&token, &[signer.jwk()]).map(|_| ()),
            Err(IdTokenError::Signature)
        );
    }

    /// Header parameters that point at other keys (`jku`, `x5u`, `x5c`, `jwk`) are
    /// ignored: a token validly signed by the key they name is still rejected.
    #[test]
    fn test_id_token_header_key_references_ignored() {
        let legit = Signer::es256("key");

        // The raw signing works: with the attacker's key in the JWKS, it verifies.
        let (token, attacker_jwk) =
            sign_raw_es256(&json!({"alg": "ES256", "kid": "key"}), &valid_claims());
        verify(&token, &[attacker_jwk]).expect("control token must verify");

        let x5c = b64(&json!("not a certificate"));
        let headers = [
            json!({"alg": "ES256", "kid": "key", "jku": "https://evil.example.com/jwks"}),
            json!({"alg": "ES256", "kid": "key", "x5u": "https://evil.example.com/cert.pem"}),
            json!({"alg": "ES256", "kid": "key", "x5c": [x5c]}),
            json!({
                "alg": "ES256", "kid": "key",
                "jku": "https://evil.example.com/jwks",
                "x5u": "https://evil.example.com/cert.pem",
                "x5c": [x5c],
            }),
            json!({"alg": "ES256", "jku": "https://evil.example.com/jwks"}),
        ];
        for header in headers {
            let (token, attacker_jwk) = sign_raw_es256(&header, &valid_claims());
            // The legitimate key is tried and fails, nothing else is used.
            assert_eq!(
                verify(&token, &[legit.jwk()]).map(|_| ()),
                Err(IdTokenError::Signature),
                "{header} must be rejected"
            );
            // Embedding the attacker's key as `jwk` as well changes nothing.
            let mut with_jwk = header.clone();
            if let Some(map) = with_jwk.as_object_mut() {
                map.insert(
                    "jwk".to_string(),
                    serde_json::to_value(&attacker_jwk).expect("invalid jwk"),
                );
            }
            let (token, _) = sign_raw_es256(&with_jwk, &valid_claims());
            assert_eq!(
                verify(&token, &[legit.jwk()]).map(|_| ()),
                Err(IdTokenError::Signature),
                "{with_jwk} must be rejected"
            );
        }
    }

    fn assert_claims_denied(changes: &serde_json::Value, expected: IdTokenError) {
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&claims_with(changes));
        assert_eq!(
            verify(&token, &[signer.jwk()]).map(|_| ()),
            Err(expected),
            "{changes} must be denied"
        );
    }

    fn assert_claims_accepted(changes: &serde_json::Value) {
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&claims_with(changes));
        verify(&token, &[signer.jwk()])
            .unwrap_or_else(|err| panic!("{changes} must be accepted: {err:?}"));
    }

    #[test]
    fn test_id_token_issuer() {
        assert_claims_accepted(&json!({"iss": format!("{ISSUER}/")}));
        for iss in [
            json!(format!("{ISSUER}//")),
            json!(format!("{ISSUER}///")),
            json!("https://idp.example.com/realms/other"),
            json!("https://idp.example.com/realms/main/extra"),
            json!("http://idp.example.com/realms/main"),
            json!("https://evil.example.com/realms/main"),
            json!(""),
            json!(null),
        ] {
            assert!(matches!(
                verify_changes(&json!({ "iss": iss })),
                Err(IdTokenError::Claims(_))
            ));
        }

        // A configured issuer with a trailing `/` (a bare origin is always stored with
        // one): one `/` is ignored on either side, never more.
        let signer = Signer::es256("key");
        for (configured, iss, accepted) in [
            ("https://idp.example.com", "https://idp.example.com", true),
            ("https://idp.example.com", "https://idp.example.com/", true),
            (
                "https://idp.example.com",
                "https://idp.example.com//",
                false,
            ),
            (
                "https://idp.example.com/realms/main/",
                "https://idp.example.com/realms/main",
                true,
            ),
            (
                "https://idp.example.com/realms/main//",
                "https://idp.example.com/realms/main",
                false,
            ),
        ] {
            let configured = Url::parse(configured).expect("invalid issuer");
            let token = signer.sign_with_kid(&claims_with(&json!({ "iss": iss })));
            assert_eq!(
                verify_with_issuer(&token, &[signer.jwk()], &configured).is_ok(),
                accepted,
                "{iss} for {configured}"
            );
        }
    }

    fn verify_changes(changes: &serde_json::Value) -> Result<(), IdTokenError> {
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&claims_with(changes));
        verify(&token, &[signer.jwk()]).map(|_| ())
    }

    #[test]
    fn test_id_token_audience() {
        assert_claims_accepted(&json!({"aud": [CLIENT_ID]}));
        assert_claims_accepted(&json!({"aud": [CLIENT_ID], "azp": CLIENT_ID}));
        assert_claims_accepted(&json!({"aud": ["other", CLIENT_ID], "azp": CLIENT_ID}));

        for changes in [
            json!({"aud": "other"}),
            json!({"aud": ["other", "another"]}),
            json!({"aud": "KUBIDM"}),
            json!({"aud": []}),
            json!({"aud": null}),
            // Several audiences: azp is required, and must be us.
            json!({"aud": ["other", CLIENT_ID]}),
            json!({"aud": ["other", CLIENT_ID], "azp": "other"}),
            // A single audience with a different authorised party.
            json!({"aud": CLIENT_ID, "azp": "other"}),
        ] {
            assert!(
                matches!(verify_changes(&changes), Err(IdTokenError::Claims(_))),
                "{changes} must be denied"
            );
        }
    }

    #[test]
    fn test_id_token_times() {
        let now = NOW as i64;
        let skew = ID_TOKEN_CLOCK_SKEW.as_secs() as i64;

        // Expired, beyond the allowed skew.
        for exp in [now - skew, now - 3600, 0, i64::MIN] {
            assert_claims_denied(&json!({"exp": exp}), IdTokenError::Claims("has expired"));
        }
        assert_claims_accepted(&json!({"exp": now - skew + 1}));
        assert_claims_denied(&json!({"exp": null}), IdTokenError::Claims("has no expiry"));

        // Issued in the future, beyond the allowed skew.
        assert_claims_accepted(&json!({"iat": now + skew}));
        assert_claims_denied(
            &json!({"iat": now + skew + 1}),
            IdTokenError::Claims("was issued in the future"),
        );
        assert_claims_denied(
            &json!({"iat": i64::MAX}),
            IdTokenError::Claims("was issued in the future"),
        );
        assert_claims_denied(
            &json!({"iat": null}),
            IdTokenError::Claims("has no issued at time"),
        );

        assert_claims_accepted(&json!({"nbf": now + skew}));
        assert_claims_denied(
            &json!({"nbf": now + skew + 1}),
            IdTokenError::Claims("is not valid yet"),
        );
    }

    #[test]
    fn test_id_token_nonce() {
        for nonce in [json!("another-nonce"), json!(""), json!(null)] {
            assert_claims_denied(
                &json!({ "nonce": nonce }),
                IdTokenError::Claims("has a different nonce"),
            );
        }
    }

    #[test]
    fn test_id_token_subject() {
        for sub in [
            json!("attacker"),
            json!(""),
            json!(SUBJECT.to_uppercase()),
            json!(null),
        ] {
            assert_claims_denied(&json!({ "sub": sub }), IdTokenError::Subject);
        }
    }

    /// The session time is used, not the wall clock.
    #[test]
    fn test_id_token_uses_session_time() {
        let signer = Signer::es256("key");
        let token = signer.sign_with_kid(&claims_with(&json!({"exp": 1_000, "iat": 900})));
        let id_token = parse_id_token(&token).expect("must parse");
        let issuer = issuer();
        let expect = IdTokenExpectations {
            issuer: &issuer,
            client_id: CLIENT_ID,
            nonce: NONCE,
            subject: SUBJECT,
        };
        verify_id_token(
            &id_token,
            &[signer.jwk()],
            &expect,
            Duration::from_secs(950),
        )
        .expect("valid at the session time");
        assert!(verify_id_token(
            &id_token,
            &[signer.jwk()],
            &expect,
            Duration::from_secs(NOW)
        )
        .is_err());
    }
}
