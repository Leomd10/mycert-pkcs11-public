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
use mycert_broker::{boxed, debug_log, split_digest_info, Broker, CertificateWire, SignParams};
use std::collections::HashMap;
use std::sync::{Arc, Once, RwLock};

static FUNCTION_LIST: OnceCell<CK_FUNCTION_LIST> = OnceCell::new();
static BACKEND_REGISTERED: Once = Once::new();
static BACKEND_STATE: OnceCell<Arc<Broker>> = OnceCell::new();
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

#[derive(Debug)]
struct MyCertBackend {
    state: Arc<Broker>,
}

impl MyCertBackend {
    fn certificate_objects(&self) -> BackendResult<Vec<Box<dyn Certificate>>> {
        let mut objetos: Vec<Box<dyn Certificate>> = Vec::new();
        for wire in self.state.certificates()? {
            // Cada certificado da cadeia também vira um objeto PKCS#11 próprio, para
            // que o consumidor (Java/PJe) consiga montar a corrente de confiança até a
            // raiz ICP-Brasil. Sem isso o teste do PJeOffice reporta a cadeia ausente.
            for (indice, chain_b64) in wire.chain_der_b64.iter().enumerate() {
                match build_chain_certificate(&wire.id, indice, chain_b64, Arc::clone(&self.state)) {
                    Ok(certificado) => objetos.push(certificado),
                    // Um elo inválido não pode derrubar a listagem inteira: o certificado
                    // do titular ainda é utilizável, só a validação da cadeia fica incompleta.
                    Err(erro) => debug_log(&format!("  -> cadeia: elo {indice} ignorado ({erro})")),
                }
            }
            objetos.push(build_certificate(wire, Arc::clone(&self.state))?);
        }
        Ok(objetos)
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

fn build_certificate(wire: CertificateWire, state: Arc<Broker>) -> BackendResult<Box<dyn Certificate>> {
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

/// Monta um objeto PKCS#11 para um certificado intermediário da cadeia. A chave pública
/// é extraída do próprio certificado (SubjectPublicKeyInfo), já que a cadeia não traz
/// esse dado separado — e o rótulo sai do CN do emissor, para ficar reconhecível na
/// listagem do consumidor.
fn build_chain_certificate(
    id_base: &str,
    indice: usize,
    chain_b64: &str,
    state: Arc<Broker>,
) -> BackendResult<Box<dyn Certificate>> {
    let der = STANDARD
        .decode(chain_b64.trim())
        .map_err(|error| boxed(format!("invalid chain certificate DER: {error}")))?;
    let certificado = x509_cert::Certificate::from_der(&der)
        .map_err(|error| boxed(format!("invalid chain certificate: {error}")))?;
    let spki_der = certificado
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| boxed(format!("invalid chain SubjectPublicKeyInfo: {error}")))?;

    let id = format!("{id_base}-ca{indice}").into_bytes();
    let label = certificado.tbs_certificate.subject.to_string();
    let public_key = RemotePublicKey {
        id: id.clone(),
        label: label.clone(),
        der: spki_der,
        algorithm: KeyAlgorithm::Rsa,
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
    _state: Arc<Broker>,
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
    state: Arc<Broker>,
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
        let (payload, hash_algorithm, signature_format) = prepare_hash(algorithm, data);
        self.state.sign(&SignParams {
            certificate_alias: &self.certificate_alias,
            id: &String::from_utf8_lossy(&self.id),
            label: &self.label,
            payload: &payload,
            hash_algorithm: &hash_algorithm,
            signature_format: &signature_format,
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(
    ppFunctionList: CK_FUNCTION_LIST_PTR_PTR,
) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let state = BACKEND_STATE.get_or_init(|| Arc::new(Broker::from_env())).clone();
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
