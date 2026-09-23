//! Key Storage Provider (CNG) do MyCert.
//!
//! O certificado fica no repositório do Windows (CurrentUser\My) com uma
//! CERT_KEY_PROV_INFO apontando para este provedor e para a chave `mycert-<thumbprint>`.
//! Quando um programa assina com ele — Edge e Chrome no login por certificado, Adobe,
//! Office — o Windows carrega esta DLL e chama `SignHash`, que encaminha o hash ao broker
//! local, exatamente como o `C_Sign` do módulo PKCS#11. É o mesmo modelo do SafeID
//! Desktop, que registra o "SafeID Key Storage Provider" do mesmo jeito.
//!
//! Só existe o necessário para assinar: a chave não é criada, importada, exportada
//! (a parte privada) nem usada para decifrar. Tudo isso responde NTE_NOT_SUPPORTED.

#![cfg(windows)]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod key;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use key::{PROVIDER_NAME, RsaPublic, hash_oid, thumbprint, thumbprint_from_key_name};
use mycert_broker::{Broker, SignParams, debug_log, split_digest_info};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{
    NTE_BAD_KEYSET, NTE_BUFFER_TOO_SMALL, NTE_FAIL, NTE_INVALID_HANDLE, NTE_INVALID_PARAMETER,
    NTE_NO_MEMORY, NTE_NO_MORE_ITEMS, NTE_NOT_SUPPORTED, NTSTATUS,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_INTERFACE_VERSION, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO,
    BCryptBufferDesc, CERT_FIND_SHA1_HASH, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, CertCloseStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertOpenStore, NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION,
    NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_KEY_HANDLE, NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE, NCRYPT_SIGNATURE_OPERATION, NCryptAlgorithmName,
    NCryptKeyName, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows_sys::core::{HRESULT, PCWSTR, PWSTR};

const OK: HRESULT = 0;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as i32;

static BROKER: OnceLock<Broker> = OnceLock::new();

fn broker() -> &'static Broker {
    BROKER.get_or_init(Broker::from_env)
}

/// Cada linha do log diz qual programa carregou a DLL: a mesma DLL roda ao mesmo tempo
/// dentro do Edge, do Chrome e da ferramenta de teste, e o arquivo de log é um só.
fn log(line: &str) {
    static PROCESSO: OnceLock<String> = OnceLock::new();
    let processo = PROCESSO.get_or_init(|| {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "?".into());
        format!("{exe}#{}", std::process::id())
    });
    debug_log(&format!("KSP {processo} {line}"));
}

// ---------------------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------------------

const PROVIDER_MAGIC: u32 = 0x4D43_5056; // "MCPV"
const KEY_MAGIC: u32 = 0x4D43_4B59; // "MCKY"

struct Provider {
    magic: u32,
}

struct Key {
    magic: u32,
    name: String,
    certificate_der: Vec<u8>,
    thumbprint: [u8; 20],
    public: RsaPublic,
}

unsafe fn provider<'a>(handle: NCRYPT_PROV_HANDLE) -> Option<&'a Provider> {
    let provider = unsafe { (handle as *const Provider).as_ref()? };
    (provider.magic == PROVIDER_MAGIC).then_some(provider)
}

unsafe fn key<'a>(handle: NCRYPT_KEY_HANDLE) -> Option<&'a Key> {
    let key = unsafe { (handle as *const Key).as_ref()? };
    (key.magic == KEY_MAGIC).then_some(key)
}

/// Toda entrada da tabela passa por aqui: um panic dentro de um callback FFI abortaria o
/// processo hospedeiro — no caso, o navegador do usuário.
fn guard(nome: &str, f: impl FnOnce() -> HRESULT) -> HRESULT {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(status) => status,
        Err(_) => {
            log(&format!("{nome}: panic capturado; devolvendo NTE_FAIL"));
            NTE_FAIL
        }
    }
}

unsafe fn wide(p: PCWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) }))
}

fn utf16_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

/// Protocolo de saída do CNG: sem buffer, só informa o tamanho; buffer pequeno, informa o
/// tamanho e devolve NTE_BUFFER_TOO_SMALL; senão copia.
unsafe fn write_output(output: *mut u8, capacity: u32, result: *mut u32, value: &[u8]) -> HRESULT {
    if result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    unsafe { *result = value.len() as u32 };
    if output.is_null() {
        return OK;
    }
    if (capacity as usize) < value.len() {
        return NTE_BUFFER_TOO_SMALL;
    }
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len()) };
    OK
}

// ---------------------------------------------------------------------------------------
// Buffers entregues ao chamador (liberados depois pelo nosso FreeBuffer)
// ---------------------------------------------------------------------------------------

const BUFFER_HEADER: usize = 16;

fn alloc_buffer(size: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size + BUFFER_HEADER, BUFFER_HEADER) else {
        return std::ptr::null_mut();
    };
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        return base;
    }
    unsafe {
        (base as *mut usize).write(size);
        base.add(BUFFER_HEADER)
    }
}

unsafe fn free_buffer(p: *mut u8) {
    if p.is_null() {
        return;
    }
    unsafe {
        let base = p.sub(BUFFER_HEADER);
        let size = (base as *const usize).read();
        dealloc(base, Layout::from_size_align_unchecked(size + BUFFER_HEADER, BUFFER_HEADER));
    }
}

// ---------------------------------------------------------------------------------------
// Localização do certificado
// ---------------------------------------------------------------------------------------

/// Procura o certificado pelo thumbprint no repositório "My" do usuário e depois no da
/// máquina. É daí que sai a chave pública: assim o certificado aparece para os programas
/// mesmo com o app MyCert fechado — o broker só é necessário na hora de assinar.
fn find_certificate(thumb: &[u8; 20]) -> Option<Vec<u8>> {
    for location in [CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE] {
        if let Some(der) = unsafe { find_in_store(thumb, location) } {
            return Some(der);
        }
    }
    // Reserva: o certificado ainda não foi importado, mas o app está aberto.
    let certificados = broker().certificates().ok()?;
    certificados.into_iter().find_map(|wire| {
        let der = STANDARD.decode(wire.der_b64.trim()).ok()?;
        (thumbprint(&der) == *thumb).then_some(der)
    })
}

unsafe fn find_in_store(thumb: &[u8; 20], location: u32) -> Option<Vec<u8>> {
    let nome: Vec<u16> = "MY".encode_utf16().chain(std::iter::once(0)).collect();
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
            nome.as_ptr() as *const c_void,
        )
    };
    if store.is_null() {
        return None;
    }
    let blob = CRYPT_INTEGER_BLOB { cbData: 20, pbData: thumb.as_ptr() as *mut u8 };
    let context = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            &blob as *const CRYPT_INTEGER_BLOB as *const c_void,
            std::ptr::null(),
        )
    };
    let der = unsafe { context.as_ref() }.map(|c| {
        unsafe { std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize) }.to_vec()
    });
    unsafe {
        if !context.is_null() {
            CertFreeCertificateContext(context);
        }
        CertCloseStore(store, 0);
    }
    der
}

// ---------------------------------------------------------------------------------------
// Provedor
// ---------------------------------------------------------------------------------------

unsafe extern "system" fn open_provider(handle: *mut NCRYPT_PROV_HANDLE, _name: PCWSTR, _flags: u32) -> HRESULT {
    guard("OpenProvider", || {
        if handle.is_null() {
            return NTE_INVALID_PARAMETER;
        }
        let provider = Box::new(Provider { magic: PROVIDER_MAGIC });
        unsafe { *handle = Box::into_raw(provider) as NCRYPT_PROV_HANDLE };
        OK
    })
}

unsafe extern "system" fn free_provider(handle: NCRYPT_PROV_HANDLE) -> HRESULT {
    guard("FreeProvider", || {
        if unsafe { provider(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        drop(unsafe { Box::from_raw(handle as *mut Provider) });
        OK
    })
}

unsafe extern "system" fn get_provider_property(
    handle: NCRYPT_PROV_HANDLE,
    property: PCWSTR,
    output: *mut u8,
    capacity: u32,
    result: *mut u32,
    _flags: u32,
) -> HRESULT {
    guard("GetProviderProperty", || {
        if unsafe { provider(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        let nome = unsafe { wide(property) }.unwrap_or_default();
        let valor = match nome.as_str() {
            "Name" => utf16_bytes(PROVIDER_NAME),
            "Impl Type" => NCRYPT_IMPL_HARDWARE_FLAG.to_le_bytes().to_vec(),
            "Version" => 0x0001_0000_u32.to_le_bytes().to_vec(),
            "Max Name Length" => 260_u32.to_le_bytes().to_vec(),
            _ => {
                log(&format!("GetProviderProperty '{nome}': nao suportada"));
                return NTE_NOT_SUPPORTED;
            }
        };
        unsafe { write_output(output, capacity, result, &valor) }
    })
}

/// Propriedades que chegam antes de uma assinatura (janela-pai, contexto de uso, PIN) e
/// só fazem sentido para provedores que mostram interface própria. Recusá-las faria
/// alguns chamadores desistirem da chave; aceitamos e ignoramos.
const PROPRIEDADES_IGNORADAS: &[&str] =
    &["HWND Handle", "Use Context", "SmartCardPin", "SmartCardSecurePin", "SmartCardReader"];

unsafe extern "system" fn set_provider_property(
    handle: NCRYPT_PROV_HANDLE,
    property: PCWSTR,
    _input: *const u8,
    _size: u32,
    _flags: u32,
) -> HRESULT {
    guard("SetProviderProperty", || {
        if unsafe { provider(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        let nome = unsafe { wide(property) }.unwrap_or_default();
        if PROPRIEDADES_IGNORADAS.contains(&nome.as_str()) {
            return OK;
        }
        log(&format!("SetProviderProperty '{nome}': nao suportada"));
        NTE_NOT_SUPPORTED
    })
}

unsafe extern "system" fn is_alg_supported(handle: NCRYPT_PROV_HANDLE, alg: PCWSTR, _flags: u32) -> HRESULT {
    guard("IsAlgSupported", || {
        if unsafe { provider(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        match unsafe { wide(alg) }.as_deref() {
            Some("RSA") => OK,
            _ => NTE_NOT_SUPPORTED,
        }
    })
}

unsafe extern "system" fn enum_algorithms(
    handle: NCRYPT_PROV_HANDLE,
    operations: u32,
    count: *mut u32,
    list: *mut *mut NCryptAlgorithmName,
    _flags: u32,
) -> HRESULT {
    guard("EnumAlgorithms", || {
        if unsafe { provider(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        if count.is_null() || list.is_null() {
            return NTE_INVALID_PARAMETER;
        }
        let pedidas = NCRYPT_SIGNATURE_OPERATION | NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
        if operations != 0 && operations & pedidas == 0 {
            return NTE_NOT_SUPPORTED;
        }
        // Estrutura e nome no mesmo bloco, para um único FreeBuffer liberar tudo.
        let nome: Vec<u16> = "RSA".encode_utf16().chain(std::iter::once(0)).collect();
        let tamanho_struct = size_of::<NCryptAlgorithmName>();
        let buffer = alloc_buffer(tamanho_struct + nome.len() * 2);
        if buffer.is_null() {
            return NTE_NO_MEMORY;
        }
        unsafe {
            let texto = buffer.add(tamanho_struct) as *mut u16;
            std::ptr::copy_nonoverlapping(nome.as_ptr(), texto, nome.len());
            (buffer as *mut NCryptAlgorithmName).write(NCryptAlgorithmName {
                pszName: texto as PWSTR,
                dwClass: NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE,
                dwAlgOperations: NCRYPT_SIGNATURE_OPERATION,
                dwFlags: 0,
            });
            *count = 1;
            *list = buffer as *mut NCryptAlgorithmName;
        }
        OK
    })
}

unsafe extern "system" fn enum_keys(
    handle: NCRYPT_PROV_HANDLE,
    _scope: PCWSTR,
    _key_name: *mut *mut NCryptKeyName,
    _state: *mut *mut c_void,
    _flags: u32,
) -> HRESULT {
    // As chaves não ficam guardadas no provedor: cada uma é "aberta" a partir do
    // certificado já vinculado no repositório. Não há o que enumerar.
    guard("EnumKeys", || if unsafe { provider(handle) }.is_none() { NTE_INVALID_HANDLE } else { NTE_NO_MORE_ITEMS })
}

unsafe extern "system" fn free_buffer_fn(buffer: *mut c_void) -> HRESULT {
    guard("FreeBuffer", || {
        unsafe { free_buffer(buffer as *mut u8) };
        OK
    })
}

// ---------------------------------------------------------------------------------------
// Chave
// ---------------------------------------------------------------------------------------

unsafe extern "system" fn open_key(
    provider_handle: NCRYPT_PROV_HANDLE,
    handle: *mut NCRYPT_KEY_HANDLE,
    name: PCWSTR,
    _legacy_key_spec: u32,
    _flags: u32,
) -> HRESULT {
    guard("OpenKey", || {
        if unsafe { provider(provider_handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        if handle.is_null() {
            return NTE_INVALID_PARAMETER;
        }
        let nome = unsafe { wide(name) }.unwrap_or_default();
        let Some(thumb) = thumbprint_from_key_name(&nome) else {
            log(&format!("OpenKey '{nome}': nome fora do padrao mycert-<thumbprint>"));
            return NTE_BAD_KEYSET;
        };
        let Some(certificate_der) = find_certificate(&thumb) else {
            log(&format!("OpenKey '{nome}': certificado nao encontrado no repositorio nem no broker"));
            return NTE_BAD_KEYSET;
        };
        let Some(public) = RsaPublic::from_certificate(&certificate_der) else {
            log(&format!("OpenKey '{nome}': chave publica nao e RSA"));
            return NTE_NOT_SUPPORTED;
        };
        log(&format!("OpenKey '{nome}': RSA {} bits", public.bits()));
        let key = Box::new(Key { magic: KEY_MAGIC, name: nome, certificate_der, thumbprint: thumb, public });
        unsafe { *handle = Box::into_raw(key) as NCRYPT_KEY_HANDLE };
        OK
    })
}

unsafe extern "system" fn free_key(_provider: NCRYPT_PROV_HANDLE, handle: NCRYPT_KEY_HANDLE) -> HRESULT {
    guard("FreeKey", || {
        if unsafe { key(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        drop(unsafe { Box::from_raw(handle as *mut Key) });
        OK
    })
}

unsafe extern "system" fn get_key_property(
    _provider: NCRYPT_PROV_HANDLE,
    handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    output: *mut u8,
    capacity: u32,
    result: *mut u32,
    _flags: u32,
) -> HRESULT {
    guard("GetKeyProperty", || {
        let Some(key) = (unsafe { key(handle) }) else {
            return NTE_INVALID_HANDLE;
        };
        let nome = unsafe { wide(property) }.unwrap_or_default();
        let dword = |v: u32| v.to_le_bytes().to_vec();
        let bits = key.public.bits();
        let valor = match nome.as_str() {
            "Algorithm Name" | "Algorithm Group" => utf16_bytes("RSA"),
            "Name" | "Unique Name" => utf16_bytes(&key.name),
            "Length" => dword(bits),
            // NCRYPT_SUPPORTED_LENGTHS: mínimo, máximo, incremento e padrão. A chave já
            // existe e não muda de tamanho, então os três limites são o próprio tamanho.
            "Lengths" => [bits, bits, 8, bits].iter().flat_map(|v| v.to_le_bytes()).collect(),
            "Block Length" => dword(key.public.signature_len() as u32),
            "Key Usage" => dword(NCRYPT_ALLOW_SIGNING_FLAG),
            "Export Policy" => dword(0),
            "Key Type" => dword(0),
            "Impl Type" => dword(NCRYPT_IMPL_HARDWARE_FLAG),
            "SmartCardKeyCertificate" => key.certificate_der.clone(),
            _ => {
                log(&format!("GetKeyProperty '{nome}': nao suportada"));
                return NTE_NOT_SUPPORTED;
            }
        };
        unsafe { write_output(output, capacity, result, &valor) }
    })
}

unsafe extern "system" fn set_key_property(
    _provider: NCRYPT_PROV_HANDLE,
    handle: NCRYPT_KEY_HANDLE,
    property: PCWSTR,
    _input: *const u8,
    _size: u32,
    _flags: u32,
) -> HRESULT {
    guard("SetKeyProperty", || {
        if unsafe { key(handle) }.is_none() {
            return NTE_INVALID_HANDLE;
        }
        let nome = unsafe { wide(property) }.unwrap_or_default();
        if PROPRIEDADES_IGNORADAS.contains(&nome.as_str()) {
            return OK;
        }
        log(&format!("SetKeyProperty '{nome}': nao suportada"));
        NTE_NOT_SUPPORTED
    })
}

unsafe extern "system" fn export_key(
    _provider: NCRYPT_PROV_HANDLE,
    handle: NCRYPT_KEY_HANDLE,
    export_key: NCRYPT_KEY_HANDLE,
    blob_type: PCWSTR,
    _parameters: *const BCryptBufferDesc,
    output: *mut u8,
    capacity: u32,
    result: *mut u32,
    _flags: u32,
) -> HRESULT {
    guard("ExportKey", || {
        let Some(key) = (unsafe { key(handle) }) else {
            return NTE_INVALID_HANDLE;
        };
        if export_key != 0 {
            return NTE_NOT_SUPPORTED;
        }
        let tipo = unsafe { wide(blob_type) }.unwrap_or_default();
        let blob = match tipo.as_str() {
            "RSAPUBLICBLOB" | "PUBLICBLOB" => key.public.bcrypt_blob(),
            "CAPIPUBLICBLOB" => match key.public.capi_blob() {
                Some(blob) => blob,
                None => return NTE_NOT_SUPPORTED,
            },
            _ => {
                // Inclui qualquer pedido pela parte privada: ela não existe aqui.
                log(&format!("ExportKey '{tipo}': nao suportado"));
                return NTE_NOT_SUPPORTED;
            }
        };
        unsafe { write_output(output, capacity, result, &blob) }
    })
}

/// Traduz o pedido do CNG para o vocabulário da API: hash puro, OID e formato.
unsafe fn prepare(padding: *const c_void, hash: &[u8], flags: u32) -> Result<(Vec<u8>, String, &'static str), HRESULT> {
    let algoritmo = |p: PCWSTR| -> Result<(&'static str, usize), HRESULT> {
        let nome = unsafe { wide(p) }.unwrap_or_default();
        hash_oid(&nome).ok_or_else(|| {
            log(&format!("SignHash: algoritmo de hash '{nome}' nao suportado"));
            NTE_NOT_SUPPORTED
        })
    };
    if flags & BCRYPT_PAD_PKCS1 != 0 {
        let info = padding as *const BCRYPT_PKCS1_PADDING_INFO;
        let alg = unsafe { info.as_ref() }.map_or(std::ptr::null(), |i| i.pszAlgId);
        if alg.is_null() {
            // Sem algoritmo, o chamador já mandou o DigestInfo pronto (o mesmo formato
            // que o Firefox usa no TLS via PKCS#11). Se nem isso for, é o hash MD5+SHA1
            // do TLS 1.0/1.1, que a API não tem como assinar.
            return split_digest_info(hash).map(|(digest, oid)| (digest, oid, "RAW")).ok_or_else(|| {
                log(&format!("SignHash: PKCS#1 sem algoritmo e sem DigestInfo ({} bytes)", hash.len()));
                NTE_NOT_SUPPORTED
            });
        }
        let (oid, tamanho) = algoritmo(alg)?;
        if hash.len() != tamanho {
            return Err(NTE_INVALID_PARAMETER);
        }
        return Ok((hash.to_vec(), oid.to_string(), "RAW"));
    }
    if flags & BCRYPT_PAD_PSS != 0 {
        // A API da SafeWeb só assina PKCS#1: com signature_format "PSS" ela responde
        // "O signature_format do hash é inválido" (testado com `mycert-ksp-tool testar
        // --pss`). Recusar aqui, sem ir à rede, é o sinal que o chamador espera de um
        // provedor sem PSS — o TLS cai para PKCS#1 em vez de gastar uma assinatura remota.
        log("SignHash: PSS nao suportado pela API do provedor");
        return Err(NTE_NOT_SUPPORTED);
    }
    log(&format!("SignHash: padding nao suportado (flags=0x{flags:X})"));
    Err(NTE_NOT_SUPPORTED)
}

fn non_empty<'a>(first: &'a str, second: &'a str, fallback: &'a str) -> &'a str {
    if !first.is_empty() {
        first
    } else if !second.is_empty() {
        second
    } else {
        fallback
    }
}

fn sign_remote(key: &Key, payload: &[u8], hash_algorithm: &str, signature_format: &str) -> Result<Vec<u8>, String> {
    let certificados = broker()
        .certificates()
        .map_err(|e| format!("broker indisponivel (o app MyCert esta aberto?): {e}"))?;
    let wire = certificados
        .iter()
        .find(|w| STANDARD.decode(w.der_b64.trim()).is_ok_and(|der| thumbprint(&der) == key.thumbprint))
        .ok_or("o certificado nao esta configurado no app MyCert")?;
    broker()
        .sign(&SignParams {
            certificate_alias: non_empty(&wire.alias, &wire.label, &wire.id),
            id: &wire.id,
            label: non_empty(&wire.alias, &wire.label, "MyCert public key"),
            payload,
            hash_algorithm,
            signature_format,
        })
        .map_err(|e| e.to_string())
}

unsafe extern "system" fn sign_hash(
    _provider: NCRYPT_PROV_HANDLE,
    handle: NCRYPT_KEY_HANDLE,
    padding: *const c_void,
    hash: *const u8,
    hash_len: u32,
    signature: *mut u8,
    capacity: u32,
    result: *mut u32,
    flags: u32,
) -> HRESULT {
    guard("SignHash", || {
        let Some(key) = (unsafe { key(handle) }) else {
            return NTE_INVALID_HANDLE;
        };
        if result.is_null() || hash.is_null() {
            return NTE_INVALID_PARAMETER;
        }
        let tamanho = key.public.signature_len();
        if signature.is_null() {
            unsafe { *result = tamanho as u32 };
            return OK;
        }
        if (capacity as usize) < tamanho {
            unsafe { *result = tamanho as u32 };
            return NTE_BUFFER_TOO_SMALL;
        }
        let hash = unsafe { std::slice::from_raw_parts(hash, hash_len as usize) };
        log(&format!("SignHash '{}': flags=0x{flags:X} hash={} bytes", key.name, hash.len()));
        let (payload, oid, formato) = match unsafe { prepare(padding, hash, flags) } {
            Ok(pedido) => pedido,
            Err(status) => return status,
        };
        let assinatura = match sign_remote(key, &payload, &oid, formato) {
            Ok(assinatura) => assinatura,
            Err(erro) => {
                log(&format!("SignHash: falhou: {erro}"));
                return NTE_FAIL;
            }
        };
        if assinatura.len() != tamanho {
            log(&format!("SignHash: assinatura com {} bytes, esperado {tamanho}", assinatura.len()));
            return NTE_FAIL;
        }
        unsafe { write_output(signature, capacity, result, &assinatura) }
    })
}

// ---------------------------------------------------------------------------------------
// Operações que este provedor não oferece
// ---------------------------------------------------------------------------------------

macro_rules! nao_suportado {
    ($nome:ident, $rotulo:literal, ($($arg:ident: $tipo:ty),*)) => {
        unsafe extern "system" fn $nome($($arg: $tipo),*) -> HRESULT {
            $(let _ = $arg;)*
            log(concat!($rotulo, ": nao suportado"));
            NTE_NOT_SUPPORTED
        }
    };
}

nao_suportado!(create_persisted_key, "CreatePersistedKey", (a: NCRYPT_PROV_HANDLE, b: *mut NCRYPT_KEY_HANDLE, c: PCWSTR, d: PCWSTR, e: u32, f: u32));
nao_suportado!(finalize_key, "FinalizeKey", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: u32));
nao_suportado!(delete_key, "DeleteKey", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: u32));
nao_suportado!(encrypt, "Encrypt", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: *const u8, d: u32, e: *const c_void, f: *mut u8, g: u32, h: *mut u32, i: u32));
nao_suportado!(decrypt, "Decrypt", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: *const u8, d: u32, e: *const c_void, f: *mut u8, g: u32, h: *mut u32, i: u32));
nao_suportado!(import_key, "ImportKey", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: PCWSTR, d: *const BCryptBufferDesc, e: *mut NCRYPT_KEY_HANDLE, f: *const u8, g: u32, h: u32));
nao_suportado!(verify_signature, "VerifySignature", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: *const c_void, d: *const u8, e: u32, f: *const u8, g: u32, h: u32));
nao_suportado!(prompt_user, "PromptUser", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: PCWSTR, d: u32));
nao_suportado!(notify_change_key, "NotifyChangeKey", (a: NCRYPT_PROV_HANDLE, b: *mut windows_sys::Win32::Foundation::HANDLE, c: u32));
nao_suportado!(secret_agreement, "SecretAgreement", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: NCRYPT_KEY_HANDLE, d: *mut NCRYPT_SECRET_HANDLE, e: u32));
nao_suportado!(derive_key, "DeriveKey", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_SECRET_HANDLE, c: PCWSTR, d: *const BCryptBufferDesc, e: *mut u8, f: u32, g: *mut u32, h: u32));
nao_suportado!(free_secret, "FreeSecret", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_SECRET_HANDLE));
nao_suportado!(key_derivation, "KeyDerivation", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: *const BCryptBufferDesc, d: *mut u8, e: u32, f: *mut u32, g: u32));
nao_suportado!(create_claim, "CreateClaim", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: NCRYPT_KEY_HANDLE, d: u32, e: *const BCryptBufferDesc, f: *mut u8, g: u32, h: *mut u32, i: u32));
nao_suportado!(verify_claim, "VerifyClaim", (a: NCRYPT_PROV_HANDLE, b: NCRYPT_KEY_HANDLE, c: NCRYPT_KEY_HANDLE, d: u32, e: *const BCryptBufferDesc, f: *const u8, g: u32, h: *mut BCryptBufferDesc, i: u32));

// ---------------------------------------------------------------------------------------
// Ponto de entrada
// ---------------------------------------------------------------------------------------

static FUNCTION_TABLE: NCRYPT_KEY_STORAGE_FUNCTION_TABLE = NCRYPT_KEY_STORAGE_FUNCTION_TABLE {
    Version: BCRYPT_INTERFACE_VERSION { MajorVersion: 1, MinorVersion: 0 },
    OpenProvider: Some(open_provider),
    OpenKey: Some(open_key),
    CreatePersistedKey: Some(create_persisted_key),
    GetProviderProperty: Some(get_provider_property),
    GetKeyProperty: Some(get_key_property),
    SetProviderProperty: Some(set_provider_property),
    SetKeyProperty: Some(set_key_property),
    FinalizeKey: Some(finalize_key),
    DeleteKey: Some(delete_key),
    FreeProvider: Some(free_provider),
    FreeKey: Some(free_key),
    FreeBuffer: Some(free_buffer_fn),
    Encrypt: Some(encrypt),
    Decrypt: Some(decrypt),
    IsAlgSupported: Some(is_alg_supported),
    EnumAlgorithms: Some(enum_algorithms),
    EnumKeys: Some(enum_keys),
    ImportKey: Some(import_key),
    ExportKey: Some(export_key),
    SignHash: Some(sign_hash),
    VerifySignature: Some(verify_signature),
    PromptUser: Some(prompt_user),
    NotifyChangeKey: Some(notify_change_key),
    SecretAgreement: Some(secret_agreement),
    DeriveKey: Some(derive_key),
    FreeSecret: Some(free_secret),
    KeyDerivation: Some(key_derivation),
    CreateClaim: Some(create_claim),
    VerifyClaim: Some(verify_claim),
};

/// Chamada pelo roteador do NCrypt (ncrypt.dll) ao carregar o provedor registrado.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetKeyStorageInterface(
    _provider_name: PCWSTR,
    table: *mut *mut NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    _flags: u32,
) -> NTSTATUS {
    if table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { *table = &FUNCTION_TABLE as *const _ as *mut _ };
    0
}
