//! Partes do KSP que não dependem do Windows: nomes, parâmetros da chave pública e os
//! formatos de blob que o CNG espera. Ficam separadas para serem testadas com
//! `cargo test` sem passar pelo roteador do NCrypt.

use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use sha1::{Digest, Sha1};
use x509_cert::der::{Decode, Encode};

/// Nome com que o provedor é registrado no CNG e gravado na CERT_KEY_PROV_INFO.
pub const PROVIDER_NAME: &str = "MyCert Key Storage Provider";
/// Nome da DLL em System32 (valor `Image` do registro do provedor).
pub const DLL_NAME: &str = "mycert_ksp.dll";
/// Prefixo do nome da chave. O resto é o thumbprint SHA-1 do certificado — mesmo esquema
/// do SafeID (`sfwb-<thumbprint>`): o nome já diz qual certificado procurar, sem precisar
/// de nenhum arquivo de índice ao lado da DLL.
const KEY_NAME_PREFIX: &str = "mycert-";

pub fn thumbprint(certificate_der: &[u8]) -> [u8; 20] {
    Sha1::digest(certificate_der).into()
}

pub fn key_name_for(thumbprint: &[u8; 20]) -> String {
    format!("{KEY_NAME_PREFIX}{}", hex(thumbprint))
}

pub fn thumbprint_from_key_name(name: &str) -> Option<[u8; 20]> {
    let hex_part = name.strip_prefix(KEY_NAME_PREFIX)?;
    if hex_part.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex_part.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// OID e tamanho do hash para os nomes de algoritmo do CNG (`pszAlgId` do padding).
pub fn hash_oid(alg_id: &str) -> Option<(&'static str, usize)> {
    match alg_id.to_ascii_uppercase().as_str() {
        "MD5" => Some(("1.2.840.113549.2.5", 16)),
        "SHA1" => Some(("1.3.14.3.2.26", 20)),
        "SHA256" => Some(("2.16.840.1.101.3.4.2.1", 32)),
        "SHA384" => Some(("2.16.840.1.101.3.4.2.2", 48)),
        "SHA512" => Some(("2.16.840.1.101.3.4.2.3", 64)),
        _ => None,
    }
}

/// Modulus e expoente público, em big-endian e sem zeros à esquerda.
#[derive(Clone, Debug, PartialEq)]
pub struct RsaPublic {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

impl RsaPublic {
    pub fn from_certificate(certificate_der: &[u8]) -> Option<Self> {
        let certificate = x509_cert::Certificate::from_der(certificate_der).ok()?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let key = spki
            .to_der()
            .ok()
            .and_then(|der| RsaPublicKey::from_public_key_der(&der).ok())
            .or_else(|| RsaPublicKey::from_pkcs1_der(spki.subject_public_key.as_bytes()?).ok())?;
        Some(Self { modulus: key.n().to_bytes_be(), exponent: key.e().to_bytes_be() })
    }

    pub fn bits(&self) -> u32 {
        let leading = self.modulus.first().map_or(0, |b| b.leading_zeros());
        (self.modulus.len() as u32) * 8 - leading
    }

    /// Tamanho da assinatura RSA em bytes: sempre o tamanho do modulus.
    pub fn signature_len(&self) -> usize {
        (self.bits() as usize).div_ceil(8)
    }

    /// BCRYPT_RSAPUBLIC_BLOB: cabeçalho BCRYPT_RSAKEY_BLOB seguido de expoente e modulus,
    /// ambos big-endian. É o que o NCryptExportKey devolve para "RSAPUBLICBLOB".
    pub fn bcrypt_blob(&self) -> Vec<u8> {
        const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352; // "RSA1"
        let mut blob = Vec::with_capacity(24 + self.exponent.len() + self.modulus.len());
        for value in [
            BCRYPT_RSAPUBLIC_MAGIC,
            self.bits(),
            self.exponent.len() as u32,
            self.modulus.len() as u32,
            0, // cbPrime1: blob público não tem primos
            0, // cbPrime2
        ] {
            blob.extend_from_slice(&value.to_le_bytes());
        }
        blob.extend_from_slice(&self.exponent);
        blob.extend_from_slice(&self.modulus);
        blob
    }

    /// PUBLICKEYBLOB do CryptoAPI legado ("CAPIPUBLICBLOB"): PUBLICKEYSTRUC + RSAPUBKEY +
    /// modulus em little-endian. Programas antigos que chegam ao CNG pela ponte do
    /// CryptoAPI pedem este formato. Só existe para expoentes de até 32 bits.
    pub fn capi_blob(&self) -> Option<Vec<u8>> {
        const PUBLICKEYBLOB: u8 = 0x06;
        const CUR_BLOB_VERSION: u8 = 0x02;
        const CALG_RSA_KEYX: u32 = 0x0000_A400;
        const RSA1: u32 = 0x3141_5352;
        if self.exponent.len() > 4 {
            return None;
        }
        let exponent = self.exponent.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32);
        let mut blob = vec![PUBLICKEYBLOB, CUR_BLOB_VERSION, 0, 0];
        blob.extend_from_slice(&CALG_RSA_KEYX.to_le_bytes());
        blob.extend_from_slice(&RSA1.to_le_bytes());
        blob.extend_from_slice(&self.bits().to_le_bytes());
        blob.extend_from_slice(&exponent.to_le_bytes());
        let mut modulus = self.modulus.clone();
        modulus.reverse();
        modulus.resize(self.signature_len(), 0);
        blob.extend_from_slice(&modulus);
        Some(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chave_exemplo() -> RsaPublic {
        // Modulus de 2048 bits (primeiro byte com o bit alto ligado) e expoente 65537.
        let mut modulus = vec![0xC3; 256];
        modulus[255] = 0x01;
        RsaPublic { modulus, exponent: vec![0x01, 0x00, 0x01] }
    }

    #[test]
    fn nome_da_chave_ida_e_volta() {
        let thumb: [u8; 20] = std::array::from_fn(|i| i as u8 * 13);
        let nome = key_name_for(&thumb);
        assert!(nome.starts_with("mycert-"));
        assert_eq!(thumbprint_from_key_name(&nome), Some(thumb));
        // O certutil mostra o thumbprint em maiúsculas; o nome precisa aceitar os dois.
        assert_eq!(thumbprint_from_key_name(&nome.to_uppercase().replace("MYCERT-", "mycert-")), Some(thumb));
    }

    #[test]
    fn nome_de_outro_provedor_nao_vira_chave() {
        assert_eq!(thumbprint_from_key_name("sfwb-fff4e6f94f106e152bb0faf1f17cb3007829713b"), None);
        assert_eq!(thumbprint_from_key_name("mycert-abc"), None);
    }

    #[test]
    fn tamanho_em_bits_ignora_zeros_do_primeiro_byte() {
        let mut chave = chave_exemplo();
        assert_eq!(chave.bits(), 2048);
        assert_eq!(chave.signature_len(), 256);
        chave.modulus[0] = 0x7F;
        assert_eq!(chave.bits(), 2047);
        assert_eq!(chave.signature_len(), 256);
    }

    #[test]
    fn blob_bcrypt_tem_cabecalho_expoente_e_modulus() {
        let chave = chave_exemplo();
        let blob = chave.bcrypt_blob();
        assert_eq!(&blob[0..4], b"RSA1");
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), 2048);
        assert_eq!(u32::from_le_bytes(blob[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(blob[12..16].try_into().unwrap()), 256);
        assert_eq!(&blob[24..27], &[0x01, 0x00, 0x01]);
        assert_eq!(&blob[27..], chave.modulus.as_slice());
    }

    #[test]
    fn blob_capi_inverte_o_modulus() {
        let chave = chave_exemplo();
        let blob = chave.capi_blob().unwrap();
        assert_eq!(blob[0], 0x06);
        assert_eq!(u32::from_le_bytes(blob[16..20].try_into().unwrap()), 65537);
        assert_eq!(blob[20], 0x01); // último byte do modulus vem primeiro
        assert_eq!(blob.len(), 20 + 256);
    }

    #[test]
    fn oid_dos_hashes_do_cng() {
        assert_eq!(hash_oid("SHA256"), Some(("2.16.840.1.101.3.4.2.1", 32)));
        assert_eq!(hash_oid("sha1"), Some(("1.3.14.3.2.26", 20)));
        assert_eq!(hash_oid("SHA3-256"), None);
    }
}
