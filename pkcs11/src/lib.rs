#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use native_pkcs11::{CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK};
use native_pkcs11_traits::{
    register_backend, Backend, Certificate, KeyAlgorithm, KeySearchOptions, PrivateKey,
    PublicKey, Result as BackendResult, SignatureAlgorithm,
};
use once_cell::sync::OnceCell;
use pkcs11_sys::{
    CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_PRIVATE, CKA_PUBLIC_EXPONENT,
    CKA_SIGN, CKA_TOKEN, CKA_VALUE, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_GENERAL_ERROR, CKR_OK as CKR_OK_SYS,
    CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_UNAVAILABLE_INFORMATION,
    CK_USER_TYPE, CK_UTF8CHAR_PTR,
};
use pkcs11_sys::CK_ATTRIBUTE;
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use x509_cert::der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Once, RwLock};

static FUNCTION_LIST: OnceCell<CK_FUNCTION_LIST> = OnceCell::new();
static BACKEND_REGISTERED: Once = Once::new();
static BACKEND_STATE: OnceCell<Arc<BackendState>> = OnceCell::new();
// Guarda o (modulus, expoente público) de cada chave RSA, indexado pelo mesmo `id`
// usado nos objetos PKCS#11 (CKA_ID). Preenchido sempre que listamos as chaves;
// consultado pelo nosso C_GetAttributeValue quando o Java pede CKA_MODULUS ou
// CKA_PUBLIC_EXPONENT na chave privada — ver mycert_C_GetAttributeValue.
static RSA_KEY_PARAMS: OnceCell<RwLock<HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>> = OnceCell::new();

fn rsa_key_params() -> &'static RwLock<HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>> {
    RSA_KEY_PARAMS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Extrai (modulus, expoente público), em big-endian, de uma chave pública RSA em DER
/// (formato SubjectPublicKeyInfo — o mesmo que `openssl pkey -pubin -outform DER` gera).
/// Guarda o resultado em RSA_KEY_PARAMS indexado por `id`, pra o C_GetAttributeValue
/// conseguir responder CKA_MODULUS/CKA_PUBLIC_EXPONENT depois.
fn register_rsa_key_params(id: &[u8], public_key_der: &[u8]) {
    if let Ok(public_key) = RsaPublicKey::from_public_key_der(public_key_der) {
        let modulus = public_key.n().to_bytes_be();
        let exponent = public_key.e().to_bytes_be();
        rsa_key_params().write().unwrap().insert(id.to_vec(), (modulus, exponent));
    }
    // Se não for RSA (ex.: EC) ou o DER não decodificar, simplesmente não registra —
    // o C_GetAttributeValue original continua respondendo normalmente pra esses casos
    // (chaves EC não usam CKA_MODULUS/CKA_PUBLIC_EXPONENT).
}

/// Mesma coisa, mas extraindo a chave pública de DENTRO do certificado X.509 (o campo
/// `der_b64` do JSON). É esse o caminho usado na prática, porque o JSON do MyCert
/// normalmente não traz `public_key_der_b64` separado — foi exatamente isso que fazia o
/// CKA_MODULUS continuar indisponível e o Java falhar com CKR_ATTRIBUTE_TYPE_INVALID.
fn register_rsa_key_params_from_certificate(id: &[u8], certificate_der: &[u8]) {
    let Ok(certificate) = x509_cert::Certificate::from_der(certificate_der) else {
        return;
    };
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    // Caminho 1: re-serializa o SubjectPublicKeyInfo inteiro (formato que o rsa entende).
    if let Ok(spki_der) = spki.to_der() {
        if let Ok(public_key) = RsaPublicKey::from_public_key_der(&spki_der) {
            let modulus = public_key.n().to_bytes_be();
            let exponent = public_key.e().to_bytes_be();
            rsa_key_params().write().unwrap().insert(id.to_vec(), (modulus, exponent));
            return;
        }
    }
    // Caminho 2 (reserva): a chave RSA crua dentro do bit string, em formato PKCS#1.
    if let Some(raw) = spki.subject_public_key.as_bytes() {
        if let Ok(public_key) = RsaPublicKey::from_pkcs1_der(raw) {
            let modulus = public_key.n().to_bytes_be();
            let exponent = public_key.e().to_bytes_be();
            rsa_key_params().write().unwrap().insert(id.to_vec(), (modulus, exponent));
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CertificateWire {
    id: String,
    #[serde(default)]
    alias: String,
    #[serde(default)]
    label: String,
    der_b64: String,
    #[serde(default)]
    public_key_der_b64: String,
    #[serde(default = "default_algorithm")]
    algorithm: String,
}

fn default_algorithm() -> String {
    "RSA".to_string()
}

#[derive(Clone, Debug, Deserialize)]
struct CertificatesResponse {
    certificates: Vec<CertificateWire>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignResponse {
    #[serde(default)]
    raw_signature: Option<String>,
    #[serde(default)]
    signature: Option<RawSignature>,
    #[serde(default)]
    signatures: Vec<RawSignature>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawSignature {
    #[serde(default)]
    raw_signature: String,
}

#[derive(Clone, Debug, Serialize)]
struct SignRequest {
    certificate_alias: String,
    hashes: Vec<HashRequest>,
}

#[derive(Clone, Debug, Serialize)]
struct HashRequest {
    id: String,
    alias: String,
    hash: String,
    hash_algorithm: String,
    signature_format: String,
}

#[derive(Debug)]
struct BackendState {
    broker_url: String,
    session_token: RwLock<Option<String>>,
}

impl BackendState {
    fn new() -> Self {
        let broker_url = std::env::var("MYCERT_BROKER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:47891".to_string())
            .trim_end_matches('/')
            .to_string();
        Self { broker_url, session_token: RwLock::new(None) }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.broker_url, path.trim_start_matches('/'))
    }

    fn login(&self, pin: Option<&str>) -> BackendResult<()> {
        let response: BrokerLoginResponse = ureq::post(&self.url("session/login"))
            .send_json(serde_json::json!({ "pin": pin }))
            .map_err(|error| boxed(format!("broker login failed: {error}")))?
            .into_json()
            .map_err(|error| boxed(format!("invalid broker login response: {error}")))?;
        *self.session_token.write().map_err(|_| boxed("session lock poisoned"))? =
            Some(response.access_token);
        Ok(())
    }

    fn logout(&self) -> BackendResult<()> {
        *self.session_token.write().map_err(|_| boxed("session lock poisoned"))? = None;
        Ok(())
    }

    fn token(&self) -> BackendResult<String> {
        self.session_token
            .read()
            .map_err(|_| boxed("session lock poisoned"))?
            .clone()
            .ok_or_else(|| boxed("PKCS#11 session is not logged in"))
    }

    /// Devolve o token de sessão, fazendo login automaticamente se ainda não houver um.
    ///
    /// Por que isso é necessário: o SunPKCS11 só chama C_Login quando o token anuncia que
    /// exige PIN. No fluxo de autenticação do PJe ele vai direto para a assinatura, e o
    /// módulo ficava sem token ("PKCS#11 session is not logged in"). Como o login do MyCert
    /// não usa PIN de verdade (o broker apenas troca a autorização já salva no app por um
    /// token de sessão), podemos fazê-lo sob demanda, sem pedir nada ao usuário.
    fn token_or_login(&self) -> BackendResult<String> {
        if let Ok(token) = self.token() {
            return Ok(token);
        }
        debug_log("  -> sem token de sessao; tentando login automatico no broker");
        self.login(None)?;
        let token = self.token()?;
        debug_log("  -> login automatico OK");
        Ok(token)
    }

    fn certificates(&self) -> BackendResult<Vec<CertificateWire>> {
        let response: CertificatesResponse = ureq::get(&self.url("certificates"))
            .call()
            .map_err(|error| boxed(format!("certificate discovery failed: {error}")))?
            .into_json()
            .map_err(|error| boxed(format!("invalid certificate response: {error}")))?;
        Ok(response.certificates)
    }
}

#[derive(Debug)]
struct MyCertBackend {
    state: Arc<BackendState>,
}

impl MyCertBackend {
    fn certificate_objects(&self) -> BackendResult<Vec<Box<dyn Certificate>>> {
        self.state
            .certificates()?
            .into_iter()
            .map(|wire| build_certificate(wire, Arc::clone(&self.state)))
            .collect()
    }
}

impl Backend for MyCertBackend {
    fn name(&self) -> String {
        "MyCert Cloud Token".to_string()
    }

    fn find_all_certificates(&self) -> BackendResult<Vec<Box<dyn Certificate>>> {
        self.certificate_objects()
    }

    fn find_private_key(&self, query: KeySearchOptions) -> BackendResult<Option<Arc<dyn PrivateKey>>> {
        let keys = self.find_all_private_keys()?;
        Ok(keys.into_iter().find(|key| match &query {
            KeySearchOptions::Id(id) => key.id() == *id,
            KeySearchOptions::Label(label) => key.label() == *label,
        }))
    }

    fn find_public_key(&self, query: KeySearchOptions) -> BackendResult<Option<Box<dyn PublicKey>>> {
        for wire in self.state.certificates()? {
            let id = wire.id.as_bytes();
            let label = non_empty(&wire.alias, &wire.label, "MyCert public key");
            let matches = match &query {
                KeySearchOptions::Id(value) => value.as_slice() == id,
                KeySearchOptions::Label(value) => value == &label,
            };
            if !matches {
                continue;
            }
            let der = STANDARD
                .decode(wire.public_key_der_b64)
                .map_err(|error| boxed(format!("invalid public key DER: {error}")))?;
            return Ok(Some(Box::new(RemotePublicKey {
                id: id.to_vec(),
                label,
                der,
                algorithm: parse_algorithm(&wire.algorithm),
            })));
        }
        Ok(None)
    }

    fn find_all_private_keys(&self) -> BackendResult<Vec<Arc<dyn PrivateKey>>> {
        self.state
            .certificates()?
            .into_iter()
            .map(|wire| {
                let algorithm = parse_algorithm(&wire.algorithm);
                let alias = non_empty(&wire.alias, &wire.label, &wire.id);
                let id = wire.id.clone().into_bytes();
                if algorithm == KeyAlgorithm::Rsa {
                    // Preferência: chave pública explícita, se o JSON trouxer.
                    let mut registrado = false;
                    if !wire.public_key_der_b64.is_empty() {
                        if let Ok(public_key_der) = STANDARD.decode(&wire.public_key_der_b64) {
                            register_rsa_key_params(&id, &public_key_der);
                            registrado = rsa_key_params().read().unwrap().contains_key(&id);
                        }
                    }
                    // Caso normal: extrai do próprio certificado.
                    if !registrado && !wire.der_b64.is_empty() {
                        if let Ok(certificate_der) = STANDARD.decode(&wire.der_b64) {
                            register_rsa_key_params_from_certificate(&id, &certificate_der);
                        }
                    }
                }
                Ok(Arc::new(RemotePrivateKey {
                    id,
                    label: alias,
                    certificate_alias: non_empty(&wire.alias, &wire.label, &wire.id),
                    algorithm,
                    state: Arc::clone(&self.state),
                }) as Arc<dyn PrivateKey>)
            })
            .collect()
    }

    fn find_all_public_keys(&self) -> BackendResult<Vec<Arc<dyn PublicKey>>> {
        self.state
            .certificates()?
            .into_iter()
            .map(|wire| {
                let id = wire.id.into_bytes();
                let label = non_empty(&wire.alias, &wire.label, "MyCert public key");
                let der = STANDARD
                    .decode(wire.public_key_der_b64)
                    .map_err(|error| boxed(format!("invalid public key DER: {error}")))?;
                Ok(Arc::new(RemotePublicKey {
                    id,
                    label,
                    der,
                    algorithm: parse_algorithm(&wire.algorithm),
                }) as Arc<dyn PublicKey>)
            })
            .collect()
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _label: Option<&str>,
    ) -> BackendResult<Arc<dyn PrivateKey>> {
        Err(boxed("MyCert tokens do not generate keys through PKCS#11"))
    }
}

fn build_certificate(wire: CertificateWire, state: Arc<BackendState>) -> BackendResult<Box<dyn Certificate>> {
    let id = wire.id.into_bytes();
    let label = non_empty(&wire.alias, &wire.label, "MyCert certificate");
    let der = STANDARD
        .decode(wire.der_b64)
        .map_err(|error| boxed(format!("invalid certificate DER: {error}")))?;
    let public_key_der = STANDARD
        .decode(wire.public_key_der_b64)
        .map_err(|error| boxed(format!("invalid public key DER: {error}")))?;
    let public_key = RemotePublicKey {
        id: id.clone(),
        label: label.clone(),
        der: public_key_der,
        algorithm: parse_algorithm(&wire.algorithm),
    };
    Ok(Box::new(RemoteCertificate { id, label, der, public_key, _state: state }))
}

fn non_empty(first: &str, second: &str, fallback: &str) -> String {
    if !first.is_empty() {
        first.to_string()
    } else if !second.is_empty() {
        second.to_string()
    } else {
        fallback.to_string()
    }
}

fn parse_algorithm(value: &str) -> KeyAlgorithm {
    if value.eq_ignore_ascii_case("EC") || value.eq_ignore_ascii_case("ECDSA") {
        KeyAlgorithm::Ecc
    } else {
        KeyAlgorithm::Rsa
    }
}

#[derive(Debug)]
struct RemoteCertificate {
    id: Vec<u8>,
    label: String,
    der: Vec<u8>,
    public_key: RemotePublicKey,
    _state: Arc<BackendState>,
}

impl Certificate for RemoteCertificate {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    fn public_key(&self) -> &dyn PublicKey {
        &self.public_key
    }

    fn delete(self: Box<Self>) {}
}

#[derive(Debug)]
struct RemotePublicKey {
    id: Vec<u8>,
    label: String,
    der: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl PublicKey for RemotePublicKey {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    fn verify(&self, _algorithm: &SignatureAlgorithm, _data: &[u8], _signature: &[u8]) -> BackendResult<()> {
        Err(boxed("remote verification is not implemented"))
    }

    fn delete(self: Box<Self>) {}

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
}

#[derive(Debug)]
struct RemotePrivateKey {
    id: Vec<u8>,
    label: String,
    certificate_alias: String,
    algorithm: KeyAlgorithm,
    state: Arc<BackendState>,
}

impl PrivateKey for RemotePrivateKey {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> BackendResult<Vec<u8>> {
        debug_log(&format!(
            "sign() algoritmo={:?} tamanho_dados={} bytes",
            algorithm,
            data.len()
        ));
        let token = match self.state.token_or_login() {
            Ok(token) => token,
            Err(error) => {
                debug_log(&format!("  -> falhou ao obter token de sessao: {error}"));
                return Err(error);
            }
        };
        let (payload, hash_algorithm, signature_format) = prepare_hash(algorithm, data);
        debug_log(&format!(
            "  -> enviando hash_algorithm={} signature_format={} payload={} bytes inicio={}",
            hash_algorithm,
            signature_format,
            payload.len(),
            payload.iter().take(20).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("")
        ));
        let request = SignRequest {
            certificate_alias: self.certificate_alias.clone(),
            hashes: vec![HashRequest {
                id: String::from_utf8_lossy(&self.id).to_string(),
                alias: self.label.clone(),
                hash: STANDARD.encode(payload),
                hash_algorithm,
                signature_format,
            }],
        };
        let http = ureq::post(&self.state.url("sign"))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(serde_json::to_value(request).map_err(|error| boxed(error.to_string()))?);
        let http = match http {
            Ok(response) => response,
            Err(ureq::Error::Status(code, response)) => {
                let corpo = response.into_string().unwrap_or_default();
                debug_log(&format!("  -> servidor recusou a assinatura: HTTP {code} corpo={corpo}"));
                return Err(boxed(format!("remote signature failed: HTTP {code}: {corpo}")));
            }
            Err(error) => {
                debug_log(&format!("  -> falha de rede ao assinar: {error}"));
                return Err(boxed(format!("remote signature failed: {error}")));
            }
        };
        let bruto = http
            .into_string()
            .map_err(|error| boxed(format!("invalid signature response: {error}")))?;
        debug_log(&format!("  -> resposta do servidor: {bruto}"));
        let response: SignResponse = serde_json::from_str(&bruto)
            .map_err(|error| boxed(format!("invalid signature response: {error}")))?;
        let value = response
            .raw_signature
            .or_else(|| response.signature.map(|value| value.raw_signature))
            .or_else(|| response.signatures.into_iter().next().map(|value| value.raw_signature))
            .ok_or_else(|| {
                debug_log("  -> resposta sem raw_signature");
                boxed("signature response did not contain raw_signature")
            })?;
        STANDARD
            .decode(value)
            .map_err(|error| boxed(format!("invalid raw_signature Base64: {error}")))
            .inspect(|assinatura| {
                // Numa chave RSA de 2048 bits a assinatura crua tem 256 bytes. Se vier
                // muito maior, é sinal de que o PSC devolveu um envelope (CMS) em vez da
                // assinatura pura — o Java rejeitaria com CKR_ARGUMENTS_BAD.
                debug_log(&format!("  -> assinatura recebida: {} bytes", assinatura.len()));
            })
    }

    fn delete(&self) {}

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
}

fn prepare_hash(algorithm: &SignatureAlgorithm, data: &[u8]) -> (Vec<u8>, String, String) {
    use sha1::Digest as _;
    match algorithm {
        // SEMPRE "RAW": um módulo PKCS#11 deve devolver ao Java a assinatura RSA crua
        // (os bytes da operação sobre o hash). Com "CMS" o PSC devolve um envelope
        // PKCS#7 completo, com certificado e atributos assinados dentro — o Java recebe
        // algo do tamanho/formato errados e responde CKR_ARGUMENTS_BAD. Quem monta o CMS,
        // quando precisa, é a aplicação assinadora (SERPRO, PJe etc.), não este módulo.
        SignatureAlgorithm::RsaPkcs1v15Sha1 => (sha1::Sha1::digest(data).to_vec(), "1.3.14.3.2.26".to_string(), "RAW".to_string()),
        SignatureAlgorithm::RsaPkcs1v15Sha256 => (sha2::Sha256::digest(data).to_vec(), "2.16.840.1.101.3.4.2.1".to_string(), "RAW".to_string()),
        SignatureAlgorithm::RsaPkcs1v15Sha384 => (sha2::Sha384::digest(data).to_vec(), "2.16.840.1.101.3.4.2.2".to_string(), "RAW".to_string()),
        SignatureAlgorithm::RsaPkcs1v15Sha512 => (sha2::Sha512::digest(data).to_vec(), "2.16.840.1.101.3.4.2.3".to_string(), "RAW".to_string()),
        SignatureAlgorithm::RsaPss { digest, .. } => (data.to_vec(), digest_oid(digest), "PSS".to_string()),
        SignatureAlgorithm::Ecdsa => (data.to_vec(), "2.16.840.1.101.3.4.2.1".to_string(), "ECDSA".to_string()),
        // No modo cru o Java já entrega um DigestInfo DER pronto (hash + OID do
        // algoritmo lá dentro). Antes mandávamos um OID de SHA-256 fixo, mesmo quando o
        // conteúdo era de outro algoritmo — o PJe usa MD5WITHRSA, então o payload vinha
        // com OID de MD5 rotulado como SHA-256. Aqui lemos o OID de dentro do próprio
        // DigestInfo para informar o algoritmo verdadeiro.
        // O campo `hash` da API espera SÓ o hash; o OID vai separado em hash_algorithm.
        // Como no modo cru o Java entrega um DigestInfo (cabeçalho com OID + hash),
        // separamos os dois aqui em vez de mandar o bloco inteiro como se fosse o hash.
        SignatureAlgorithm::RsaRaw | SignatureAlgorithm::RsaPkcs1v15Raw => match split_digest_info(data) {
            Some((digest, oid)) => (digest, oid, "RAW".to_string()),
            None => (data.to_vec(), "2.16.840.1.101.3.4.2.1".to_string(), "RAW".to_string()),
        },
    }
}

/// Reconhece o OID do algoritmo de hash dentro de um DigestInfo DER (o formato que o
/// SunPKCS11 manda no modo cru). Comparamos pelo prefixo DER completo, que é fixo e
/// conhecido para cada algoritmo — mais simples e seguro do que escrever um parser ASN.1.
fn split_digest_info(data: &[u8]) -> Option<(Vec<u8>, String)> {
    let oid = digest_info_oid(data)?;
    let prefixo = DIGEST_INFO_PREFIXOS.iter().find(|(p, _)| data.starts_with(p))?;
    Some((data[prefixo.0.len()..].to_vec(), oid))
}

const DIGEST_INFO_PREFIXOS: &[(&[u8], &str)] = &[
    // MD5 (34 bytes no total) — é o usado pelo PJe (MD5WITHRSA).
    (&[0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10], "1.2.840.113549.2.5"),
    // SHA-1 (35 bytes)
    (&[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14], "1.3.14.3.2.26"),
    // SHA-256 (51 bytes)
    (&[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20], "2.16.840.1.101.3.4.2.1"),
    // SHA-384 (67 bytes)
    (&[0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30], "2.16.840.1.101.3.4.2.2"),
    // SHA-512 (83 bytes)
    (&[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40], "2.16.840.1.101.3.4.2.3"),
];

fn digest_info_oid(data: &[u8]) -> Option<String> {
    DIGEST_INFO_PREFIXOS
        .iter()
        .find(|(prefixo, _)| data.starts_with(prefixo))
        .map(|(_, oid)| oid.to_string())
}

fn digest_oid(digest: &native_pkcs11_traits::DigestType) -> String {
    match digest {
        native_pkcs11_traits::DigestType::Sha1 => "1.3.14.3.2.26",
        native_pkcs11_traits::DigestType::Sha224 => "2.16.840.1.101.3.4.2.4",
        native_pkcs11_traits::DigestType::Sha256 => "2.16.840.1.101.3.4.2.1",
        native_pkcs11_traits::DigestType::Sha384 => "2.16.840.1.101.3.4.2.2",
        native_pkcs11_traits::DigestType::Sha512 => "2.16.840.1.101.3.4.2.3",
    }
    .to_string()
}

#[derive(Debug, Deserialize)]
struct BrokerLoginResponse {
    access_token: String,
}

fn boxed(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(
    ppFunctionList: CK_FUNCTION_LIST_PTR_PTR,
) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let state = BACKEND_STATE.get_or_init(|| Arc::new(BackendState::new())).clone();
    BACKEND_REGISTERED.call_once(|| register_backend(Box::new(MyCertBackend { state })));
    let list = FUNCTION_LIST.get_or_init(|| {
        let mut list = unsafe { std::ptr::read(std::ptr::addr_of!(native_pkcs11::FUNC_LIST)) };
        list.C_GetFunctionList = Some(C_GetFunctionList);
        list.C_Login = Some(mycert_C_Login);
        list.C_Logout = Some(mycert_C_Logout);
        // Guarda a implementação original antes de sobrescrever, pra delegarmos tudo
        // que não seja CKA_MODULUS/CKA_PUBLIC_EXPONENT (ver mycert_C_GetAttributeValue).
        ORIGINAL_GET_ATTRIBUTE_VALUE.get_or_init(|| list.C_GetAttributeValue);
        list.C_GetAttributeValue = Some(mycert_C_GetAttributeValue);
        list
    });
    unsafe {
        *ppFunctionList = list as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
    }
    CKR_OK
}

unsafe extern "C" fn mycert_C_Login(
    _hSession: CK_SESSION_HANDLE,
    _userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    let pin = if pPin.is_null() || ulPinLen == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(pPin as *const u8, ulPinLen as usize)
        }).to_string())
    };
    match BACKEND_STATE.get() {
        Some(state) => match state.login(pin.as_deref()) {
            Ok(()) => CKR_OK,
            Err(error) => {
                eprintln!("MyCert PKCS#11 login failed: {error}");
                CKR_GENERAL_ERROR
            }
        },
        None => CKR_GENERAL_ERROR,
    }
}

static ORIGINAL_GET_ATTRIBUTE_VALUE: OnceCell<
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>,
> = OnceCell::new();

/// Log de diagnóstico do C_GetAttributeValue: registra cada atributo pedido pelo Java e o
/// que devolvemos. Serve pra descobrir QUAL atributo está causando CKR_ATTRIBUTE_TYPE_INVALID
/// (o SunPKCS11 pede vários em sequência), em vez de supor. Ativa definindo a variável de
/// ambiente MYCERT_PKCS11_LOG com o caminho do arquivo, ex.:
///   setx MYCERT_PKCS11_LOG C:\\Users\\SEU_USUARIO\\mycert_pkcs11.log
/// Sem essa variável, não escreve nada e não custa nada.
fn debug_log(line: &str) {
    if let Ok(path) = std::env::var("MYCERT_PKCS11_LOG") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{}", line);
        }
    }
}

/// Nome legível dos atributos que interessam ao diagnóstico; os demais saem em hexadecimal.
fn attr_name(t: CK_ULONG) -> String {
    match t {
        x if x == CKA_ID => "CKA_ID".into(),
        x if x == CKA_MODULUS => "CKA_MODULUS".into(),
        x if x == CKA_PUBLIC_EXPONENT => "CKA_PUBLIC_EXPONENT".into(),
        x if x == CKA_CLASS => "CKA_CLASS".into(),
        x if x == CKA_KEY_TYPE => "CKA_KEY_TYPE".into(),
        x if x == CKA_LABEL => "CKA_LABEL".into(),
        x if x == CKA_VALUE => "CKA_VALUE".into(),
        x if x == CKA_SIGN => "CKA_SIGN".into(),
        x if x == CKA_PRIVATE => "CKA_PRIVATE".into(),
        x if x == CKA_TOKEN => "CKA_TOKEN".into(),
        other => format!("0x{:X}", other),
    }
}

/// Busca o CKA_ID de um objeto chamando a implementação original (duas etapas, do jeito
/// padrão do PKCS#11: primeiro só pra saber o tamanho, depois pra pegar os bytes).
/// É assim que descobrimos de qual chave o Java está falando, sem depender de o CKA_ID vir
/// junto no mesmo template que o CKA_MODULUS.
unsafe fn fetch_object_id(
    original: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
) -> Option<Vec<u8>> {
    let mut probe = CK_ATTRIBUTE { type_: CKA_ID, pValue: std::ptr::null_mut(), ulValueLen: 0 };
    if unsafe { original(hSession, hObject, &mut probe, 1) } != CKR_OK_SYS {
        return None;
    }
    let len = probe.ulValueLen as usize;
    if len == 0 || probe.ulValueLen == CK_UNAVAILABLE_INFORMATION as CK_ULONG {
        return None;
    }
    let mut buffer = vec![0u8; len];
    let mut fetch = CK_ATTRIBUTE {
        type_: CKA_ID,
        pValue: buffer.as_mut_ptr() as *mut std::ffi::c_void,
        ulValueLen: len as CK_ULONG,
    };
    if unsafe { original(hSession, hObject, &mut fetch, 1) } != CKR_OK_SYS {
        return None;
    }
    buffer.truncate(fetch.ulValueLen as usize);
    Some(buffer)
}

/// Responde CKA_MODULUS/CKA_PUBLIC_EXPONENT para as chaves privadas RSA do MyCert, que a
/// biblioteca base não conhece. O SunPKCS11 do Java exige esses dois atributos na PRÓPRIA
/// chave privada pra montar o objeto de chave antes de assinar (ver
/// CKR_ATTRIBUTE_TYPE_INVALID em P11KeyStore.loadPkey).
///
/// Por que NÃO dá pra simplesmente "chamar a original e corrigir depois": a implementação
/// base aborta a função inteira no primeiro atributo que ela não reconhece (o `?` em
/// `type_.try_into()`), sem sequer marcar o atributo como indisponível. Então o jeito certo
/// é separar antes: atendemos os que sabemos responder e repassamos só o restante.
unsafe extern "C" fn mycert_C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    let Some(Some(original)) = ORIGINAL_GET_ATTRIBUTE_VALUE.get() else {
        return CKR_GENERAL_ERROR;
    };
    let original = *original;
    if pTemplate.is_null() || ulCount == 0 {
        return unsafe { original(hSession, hObject, pTemplate, ulCount) };
    }
    let template = unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) };

    let pedidos: Vec<String> = template
        .iter()
        .map(|a| format!("{}(buf={})", attr_name(a.type_), if a.pValue.is_null() { "nao" } else { "sim" }))
        .collect();
    debug_log(&format!("C_GetAttributeValue obj={} pede: {}", hObject, pedidos.join(", ")));

    let ours: Vec<usize> = template
        .iter()
        .enumerate()
        .filter(|(_, a)| a.type_ == CKA_MODULUS || a.type_ == CKA_PUBLIC_EXPONENT)
        .map(|(i, _)| i)
        .collect();
    if ours.is_empty() {
        let rv = unsafe { original(hSession, hObject, pTemplate, ulCount) };
        debug_log(&format!("  -> nada nosso; original devolveu rv=0x{:X}", rv));
        return rv;
    }

    // Só assumimos o atributo se realmente tivermos o valor pra essa chave; caso
    // contrário deixamos tudo com a implementação original (comportamento inalterado).
    let params_lock = rsa_key_params();
    let id = unsafe { fetch_object_id(original, hSession, hObject) };
    let values: Option<(Vec<u8>, Vec<u8>)> = id.and_then(|id| {
        params_lock.read().unwrap().get(&id).map(|(m, e)| (m.clone(), e.clone()))
    });
    let Some((modulus, exponent)) = values else {
        let rv = unsafe { original(hSession, hObject, pTemplate, ulCount) };
        debug_log(&format!("  -> nao temos params RSA p/ esse objeto; original rv=0x{:X}", rv));
        return rv;
    };

    // Repassa para a original apenas os atributos que não são nossos.
    let mut rest: Vec<CK_ATTRIBUTE> = template
        .iter()
        .enumerate()
        .filter(|(i, _)| !ours.contains(i))
        .map(|(_, a)| *a)
        .collect();
    let mut rv = CKR_OK_SYS;
    if !rest.is_empty() {
        rv = unsafe { original(hSession, hObject, rest.as_mut_ptr(), rest.len() as CK_ULONG) };
        // Devolve ao template do chamador o que a original preencheu.
        let mut k = 0usize;
        for (i, attribute) in template.iter_mut().enumerate() {
            if ours.contains(&i) {
                continue;
            }
            *attribute = rest[k];
            k += 1;
        }
    }

    // Agora preenche os nossos, respeitando o protocolo de duas etapas do PKCS#11:
    // pValue nulo = o chamador só quer saber o tamanho; buffer pequeno = não escreve.
    for &i in &ours {
        let attribute = &mut template[i];
        let value: &[u8] = if attribute.type_ == CKA_MODULUS { &modulus } else { &exponent };
        let capacity = attribute.ulValueLen as usize;
        let has_buffer = !attribute.pValue.is_null();
        attribute.ulValueLen = value.len() as CK_ULONG;
        if has_buffer {
            if capacity < value.len() {
                rv = CKR_BUFFER_TOO_SMALL;
                continue;
            }
            unsafe { std::slice::from_raw_parts_mut(attribute.pValue as *mut u8, value.len()) }
                .copy_from_slice(value);
        }
    }
    debug_log(&format!("  -> preenchemos {} atributo(s) nosso(s); rv=0x{:X}", ours.len(), rv));
    rv
}

unsafe extern "C" fn mycert_C_Logout(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    match BACKEND_STATE.get() {
        Some(state) => match state.logout() {
            Ok(()) => CKR_OK,
            Err(_) => CKR_GENERAL_ERROR,
        },
        None => CKR_OK,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // DigestInfo real de MD5 (34 bytes) — o mesmo prefixo que o PJeOffice envia via
    // MD5withRSA (ver DIAGNOSTICO-CALLBACK-SAFEID.md). Os últimos 16 bytes são só um
    // hash de exemplo, não precisam corresponder a nada real pra este teste.
    const MD5_DIGEST_INFO: [u8; 34] = [
        0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10, 0x88, 0x71, 0xD7, 0xB7, 0x6B, 0x54, 0xDC, 0x5D, 0x09, 0xFD, 0xD1, 0x71,
        0x7D, 0x1C, 0x75, 0xF3,
    ];

    #[test]
    fn reconhece_oid_do_md5_no_digest_info() {
        assert_eq!(digest_info_oid(&MD5_DIGEST_INFO), Some("1.2.840.113549.2.5".to_string()));
    }

    #[test]
    fn separa_o_hash_puro_do_cabecalho_md5() {
        let (hash, oid) = split_digest_info(&MD5_DIGEST_INFO).expect("deveria reconhecer o MD5");
        assert_eq!(oid, "1.2.840.113549.2.5");
        // Só os 16 bytes do hash, sem o cabeçalho ASN.1 — é essa separação que corrige o
        // "O OID do hash é inválido" que a API da SafeWeb devolvia quando mandávamos o
        // DigestInfo inteiro como se fosse só o hash.
        assert_eq!(hash.len(), 16);
        assert_eq!(hash, &MD5_DIGEST_INFO[18..]);
    }

    #[test]
    fn dados_sem_prefixo_conhecido_nao_reconhece_oid() {
        let dados_aleatorios = [0xAA_u8; 32];
        assert_eq!(digest_info_oid(&dados_aleatorios), None);
        assert_eq!(split_digest_info(&dados_aleatorios), None);
    }
}
