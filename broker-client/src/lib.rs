//! Cliente do broker local do MyCert (`desktop/src/broker.ts`).
//!
//! Compartilhado pelas duas "portas de entrada" nativas do certificado: o módulo PKCS#11
//! (`pkcs11/`) e o Key Storage Provider do Windows (`ksp/`). As duas só diferem em como
//! recebem o pedido de assinatura; daqui para frente — login no broker, renovação da
//! sessão, envio do hash e leitura da assinatura crua — o caminho é o mesmo.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateWire {
    pub id: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub label: String,
    pub der_b64: String,
    #[serde(default)]
    pub public_key_der_b64: String,
    /// Certificados intermediários da cadeia (AC emissora e ACs acima dela), em DER
    /// base64. Sem eles o consumidor reporta "Cadeia de Certificados: AUSENTE" — o
    /// certificado do titular sozinho não permite validar a corrente até a raiz.
    #[serde(default)]
    pub chain_der_b64: Vec<String>,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
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

/// Um pedido de assinatura já traduzido para o vocabulário da API: o hash puro (sem
/// DigestInfo), o OID do algoritmo em separado e o formato ("RAW" ou "PSS").
pub struct SignParams<'a> {
    pub certificate_alias: &'a str,
    pub id: &'a str,
    pub label: &'a str,
    pub payload: &'a [u8],
    pub hash_algorithm: &'a str,
    pub signature_format: &'a str,
}

#[derive(Debug, Deserialize)]
struct BrokerLoginResponse {
    access_token: String,
}

#[derive(Debug)]
pub struct Broker {
    broker_url: String,
    session_token: RwLock<Option<String>>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Broker {
    pub fn from_env() -> Self {
        let broker_url = std::env::var("MYCERT_BROKER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:47891".to_string())
            .trim_end_matches('/')
            .to_string();
        Self { broker_url, session_token: RwLock::new(None) }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.broker_url, path.trim_start_matches('/'))
    }

    pub fn login(&self, pin: Option<&str>) -> Result<()> {
        let response: BrokerLoginResponse = ureq::post(&self.url("session/login"))
            .send_json(serde_json::json!({ "pin": pin }))
            .map_err(|error| erro_do_broker("broker login failed", error))?
            .into_json()
            .map_err(|error| boxed(format!("invalid broker login response: {error}")))?;
        *self.session_token.write().map_err(|_| boxed("session lock poisoned"))? =
            Some(response.access_token);
        Ok(())
    }

    pub fn logout(&self) -> Result<()> {
        *self.session_token.write().map_err(|_| boxed("session lock poisoned"))? = None;
        Ok(())
    }

    fn token(&self) -> Result<String> {
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
    /// token de sessão), podemos fazê-lo sob demanda, sem pedir nada ao usuário. O KSP
    /// depende disso pelo mesmo motivo: o CNG não tem etapa de login.
    fn token_or_login(&self) -> Result<String> {
        if let Ok(token) = self.token() {
            return Ok(token);
        }
        debug_log("  -> sem token de sessao; tentando login automatico no broker");
        self.login(None)?;
        let token = self.token()?;
        debug_log("  -> login automatico OK");
        Ok(token)
    }

    pub fn certificates(&self) -> Result<Vec<CertificateWire>> {
        let response: CertificatesResponse = ureq::get(&self.url("certificates"))
            .call()
            .map_err(|error| erro_do_broker("certificate discovery failed", error))?
            .into_json()
            .map_err(|error| boxed(format!("invalid certificate response: {error}")))?;
        Ok(response.certificates)
    }

    /// Envia um hash ao broker e devolve a assinatura crua (os bytes da operação RSA).
    pub fn sign(&self, params: &SignParams) -> Result<Vec<u8>> {
        let mut token = match self.token_or_login() {
            Ok(token) => token,
            Err(error) => {
                debug_log(&format!("  -> falhou ao obter token de sessao: {error}"));
                return Err(error);
            }
        };
        debug_log(&format!(
            "  -> enviando hash_algorithm={} signature_format={} payload={} bytes inicio={}",
            params.hash_algorithm,
            params.signature_format,
            params.payload.len(),
            params.payload.iter().take(20).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("")
        ));
        let request = SignRequest {
            certificate_alias: params.certificate_alias.to_string(),
            hashes: vec![HashRequest {
                id: params.id.to_string(),
                alias: params.label.to_string(),
                hash: STANDARD.encode(params.payload),
                hash_algorithm: params.hash_algorithm.to_string(),
                signature_format: params.signature_format.to_string(),
            }],
        };
        let corpo_json = serde_json::to_value(&request).map_err(|error| boxed(error.to_string()))?;
        // Registra o corpo exato enviado. Sem isso não dá para saber em QUAL campo a API
        // reclamou: a mensagem "O OID do hash 'cert-1' é inválido" cita o `id` da entrada,
        // e sem ver o JSON completo fica ambíguo se `id` foi lido como OID ou se só nomeia
        // a entrada cujo `hash_algorithm` foi recusado.
        debug_log(&format!("  -> corpo enviado: {corpo_json}"));

        let mut renovou = false;
        let http = loop {
            let tentativa = ureq::post(&self.url("sign"))
                .set("Authorization", &format!("Bearer {token}"))
                .send_json(corpo_json.clone());
            match tentativa {
                Ok(response) => break response,
                // HTTP 401 = a sessão do broker venceu. O token fica em cache no módulo
                // enquanto o processo do assinador vive, mas o broker descarta a sessão
                // quando o access_token da SafeWeb expira (lifetime de 300s no
                // pwd_authorize). Sem renovar aqui, TODA assinatura seguinte falha até o
                // assinador ser reiniciado — inclusive assinatura de documento, que é o
                // caso de uso principal. Renova uma vez e repete a requisição.
                Err(ureq::Error::Status(401, _)) if !renovou => {
                    renovou = true;
                    debug_log("  -> sessao expirada (401); renovando o token e tentando de novo");
                    if let Err(error) = self.logout() {
                        debug_log(&format!("  -> falhou ao limpar o token: {error}"));
                        return Err(error);
                    }
                    token = match self.token_or_login() {
                        Ok(token) => token,
                        Err(error) => {
                            debug_log(&format!("  -> falhou ao renovar o token: {error}"));
                            return Err(error);
                        }
                    };
                }
                Err(ureq::Error::Status(code, response)) => {
                    let corpo = response.into_string().unwrap_or_default();
                    debug_log(&format!("  -> servidor recusou a assinatura: HTTP {code} corpo={corpo}"));
                    return Err(boxed(format!("remote signature failed: HTTP {code}: {corpo}")));
                }
                Err(error) => {
                    debug_log(&format!("  -> falha de rede ao assinar: {error}"));
                    return Err(boxed(format!("remote signature failed: {error}")));
                }
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
}

/// Reconhece o OID do algoritmo de hash dentro de um DigestInfo DER (o formato que o
/// SunPKCS11 manda no modo cru). Comparamos pelo prefixo DER completo, que é fixo e
/// conhecido para cada algoritmo — mais simples e seguro do que escrever um parser ASN.1.
pub fn split_digest_info(data: &[u8]) -> Option<(Vec<u8>, String)> {
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

pub fn digest_info_oid(data: &[u8]) -> Option<String> {
    DIGEST_INFO_PREFIXOS
        .iter()
        .find(|(prefixo, _)| data.starts_with(prefixo))
        .map(|(_, oid)| oid.to_string())
}

pub fn boxed(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

/// Converte um erro do `ureq` em mensagem legível, **lendo o corpo da resposta** quando o
/// servidor devolveu status de erro.
///
/// Por que isso é necessário: o `Display` do `ureq::Error::Status` produz apenas
/// "http://.../v1/session/login: status code 401" e descarta o corpo. O broker coloca
/// justamente no corpo a causa real (`message`), o erro original do provedor
/// (`upstream_body`) e a instrução de correção (`hint`) — tudo isso se perdia, e o log
/// ficava com um número de status que não diz o que fazer. Mesmo motivo do try/catch em
/// `broker.ts`: o erro só é útil se a causa sobreviver até quem lê o log.
fn erro_do_broker(contexto: &str, error: ureq::Error) -> Box<dyn std::error::Error> {
    match error {
        ureq::Error::Status(code, response) => {
            let corpo = response.into_string().unwrap_or_default();
            boxed(format!("{contexto}: HTTP {code}: {corpo}"))
        }
        outro => boxed(format!("{contexto}: {outro}")),
    }
}

/// Log de diagnóstico. Ativa definindo a variável de ambiente MYCERT_PKCS11_LOG com o
/// caminho do arquivo, ex.:
///   setx MYCERT_PKCS11_LOG C:\\Users\\SEU_USUARIO\\mycert_pkcs11.log
/// Sem essa variável, não escreve nada e não custa nada. O KSP escreve no mesmo arquivo,
/// com as linhas marcadas "KSP", para que uma única leitura mostre as duas portas.
pub fn debug_log(line: &str) {
    if let Ok(path) = std::env::var("MYCERT_PKCS11_LOG") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            // Horário LOCAL, com milissegundos e a data junto. A data importa porque o
            // arquivo é aberto em append e acumula sessões de dias diferentes; os
            // milissegundos mostram quanto tempo cada chamada à rede levou (a diferença
            // entre a linha "enviando" e a linha da resposta).
            let _ = writeln!(
                file,
                "[{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                line
            );
        }
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
