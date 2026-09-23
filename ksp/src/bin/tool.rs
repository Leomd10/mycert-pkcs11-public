//! mycert-ksp-tool — instala o KSP do MyCert e vincula o certificado ao repositório do Windows.
//! Rode sem argumentos para ver os comandos.

const USO: &str = "uso:
  mycert-ksp-tool instalar [--dll CAMINHO]   (administrador) copia a DLL e registra o provedor
  mycert-ksp-tool desinstalar                (administrador) desfaz o registro e apaga a DLL
  mycert-ksp-tool importar [--substituir]    vincula os certificados do app MyCert (app aberto)
  mycert-ksp-tool remover                    desfaz o vínculo e restaura o provedor anterior
  mycert-ksp-tool listar                     mostra os certificados vinculados ao MyCert
  mycert-ksp-tool testar [--pss]             assina um hash de teste pelo NCrypt e confere";

#[cfg(not(windows))]
fn main() {
    eprintln!("mycert-ksp-tool só existe no Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |nome: &str| args.iter().any(|a| a == nome);
    let resultado = match args.first().map(String::as_str) {
        Some("instalar") => {
            let dll = args.iter().position(|a| a == "--dll").and_then(|i| args.get(i + 1)).cloned();
            windows::instalar(dll)
        }
        Some("desinstalar") => windows::desinstalar(),
        Some("importar") => windows::importar(flag("--substituir")),
        Some("remover") => windows::remover(),
        Some("listar") => windows::listar().map(|_| ()),
        Some("testar") => windows::testar(flag("--pss")),
        _ => {
            eprintln!("{USO}");
            std::process::exit(2);
        }
    };
    if let Err(erro) = resultado {
        eprintln!("erro: {erro}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use mycert_broker::Broker;
    use mycert_ksp::key::{DLL_NAME, PROVIDER_NAME, RsaPublic, hex, key_name_for, thumbprint};
    use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::ffi::c_void;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::*;
    use windows_sys::core::PWSTR;

    type Resultado<T = ()> = Result<T, String>;

    fn w(texto: &str) -> Vec<u16> {
        texto.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn de_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        while unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
    }

    // -----------------------------------------------------------------------------------
    // Instalação do provedor
    // -----------------------------------------------------------------------------------

    fn system32() -> PathBuf {
        let raiz = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(raiz).join("System32")
    }

    pub fn instalar(dll: Option<String>) -> Resultado {
        let origem = match dll {
            Some(caminho) => PathBuf::from(caminho),
            None => std::env::current_exe().map_err(|e| e.to_string())?.with_file_name(DLL_NAME),
        };
        if !origem.exists() {
            return Err(format!("DLL não encontrada em {} (use --dll)", origem.display()));
        }
        let destino = system32().join(DLL_NAME);
        // Um programa que já carregou a DLL (Edge, Chrome) a mantém travada para escrita,
        // mas o Windows permite renomear um arquivo em uso. A cópia antiga some quando o
        // último processo que a usa fecha e o arquivo é apagado na próxima instalação.
        if destino.exists() && std::fs::copy(&origem, &destino).is_err() {
            let antiga = destino.with_extension(format!("dll.antiga-{}", std::process::id()));
            std::fs::rename(&destino, &antiga).map_err(|e| {
                format!("não foi possível substituir {} ({e}); rode como administrador", destino.display())
            })?;
            println!("DLL anterior em uso; renomeada para {}", antiga.display());
        }
        std::fs::copy(&origem, &destino)
            .map_err(|e| format!("não foi possível copiar para {} ({e}); rode como administrador", destino.display()))?;
        limpar_copias_antigas();
        println!("DLL copiada para {}", destino.display());

        let nome = w(PROVIDER_NAME);
        let imagem = w(DLL_NAME);
        let funcao = w("KEY_STORAGE");
        let mut funcoes = [funcao.as_ptr() as PWSTR];
        let mut interface = CRYPT_INTERFACE_REG {
            dwInterface: NCRYPT_KEY_STORAGE_INTERFACE,
            dwFlags: CRYPT_LOCAL,
            cFunctions: 1,
            rgpszFunctions: funcoes.as_mut_ptr(),
        };
        let mut interfaces = [&mut interface as *mut CRYPT_INTERFACE_REG];
        let mut modo_usuario = CRYPT_IMAGE_REG {
            pszImage: imagem.as_ptr() as PWSTR,
            cInterfaces: 1,
            rgpInterfaces: interfaces.as_mut_ptr(),
        };
        let registro = CRYPT_PROVIDER_REG {
            cAliases: 0,
            rgpszAliases: null_mut(),
            pUM: &mut modo_usuario,
            pKM: null_mut(),
        };
        let status = unsafe { BCryptRegisterProvider(nome.as_ptr(), CRYPT_OVERWRITE, &registro) };
        if status != 0 {
            return Err(format!("BCryptRegisterProvider falhou (0x{:08X}); rode como administrador", status as u32));
        }
        let contexto = w("Default");
        let status = unsafe {
            BCryptAddContextFunctionProvider(
                CRYPT_LOCAL,
                contexto.as_ptr(),
                NCRYPT_KEY_STORAGE_INTERFACE,
                funcao.as_ptr(),
                nome.as_ptr(),
                CRYPT_PRIORITY_BOTTOM,
            )
        };
        // 0xC0000035 (STATUS_OBJECT_NAME_COLLISION): já estava na lista — reinstalação.
        if status != 0 && status as u32 != 0xC000_0035 {
            return Err(format!("BCryptAddContextFunctionProvider falhou (0x{:08X})", status as u32));
        }
        println!("Provedor \"{PROVIDER_NAME}\" registrado.");
        Ok(())
    }

    fn limpar_copias_antigas() {
        if let Ok(entradas) = std::fs::read_dir(system32()) {
            for entrada in entradas.flatten() {
                if entrada.file_name().to_string_lossy().starts_with(&format!("{DLL_NAME}.antiga-")) {
                    let _ = std::fs::remove_file(entrada.path());
                }
            }
        }
    }

    pub fn desinstalar() -> Resultado {
        let nome = w(PROVIDER_NAME);
        let contexto = w("Default");
        let funcao = w("KEY_STORAGE");
        unsafe {
            BCryptRemoveContextFunctionProvider(
                CRYPT_LOCAL,
                contexto.as_ptr(),
                NCRYPT_KEY_STORAGE_INTERFACE,
                funcao.as_ptr(),
                nome.as_ptr(),
            );
            let status = BCryptUnregisterProvider(nome.as_ptr());
            if status != 0 {
                println!("BCryptUnregisterProvider: 0x{:08X} (provedor já removido?)", status as u32);
            }
        }
        let destino = system32().join(DLL_NAME);
        if destino.exists() && std::fs::remove_file(&destino).is_err() {
            let antiga = destino.with_extension(format!("dll.antiga-{}", std::process::id()));
            std::fs::rename(&destino, &antiga).map_err(|e| format!("não foi possível remover a DLL ({e})"))?;
            println!("DLL em uso; renomeada para {} (apague depois de fechar os navegadores)", antiga.display());
        }
        println!("Provedor \"{PROVIDER_NAME}\" desinstalado. Os vínculos no repositório continuam: rode `remover` antes.");
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Repositório de certificados
    // -----------------------------------------------------------------------------------

    struct Repositorio(HCERTSTORE);

    impl Repositorio {
        fn abrir(nome: &str) -> Resultado<Self> {
            let nome = w(nome);
            let store = unsafe {
                CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, nome.as_ptr() as *const c_void)
            };
            if store.is_null() {
                return Err("não foi possível abrir o repositório de certificados do usuário".into());
            }
            Ok(Self(store))
        }

        fn buscar(&self, thumb: &[u8; 20]) -> Option<Contexto> {
            let blob = CRYPT_INTEGER_BLOB { cbData: 20, pbData: thumb.as_ptr() as *mut u8 };
            let ctx = unsafe {
                CertFindCertificateInStore(
                    self.0,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SHA1_HASH,
                    &blob as *const _ as *const c_void,
                    null(),
                )
            };
            (!ctx.is_null()).then_some(Contexto(ctx))
        }

        fn adicionar(&self, der: &[u8]) -> Resultado<Contexto> {
            let mut ctx: *mut CERT_CONTEXT = null_mut();
            let ok = unsafe {
                CertAddEncodedCertificateToStore(
                    self.0,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    der.as_ptr(),
                    der.len() as u32,
                    CERT_STORE_ADD_USE_EXISTING,
                    &mut ctx,
                )
            };
            if ok == 0 || ctx.is_null() {
                return Err("CertAddEncodedCertificateToStore falhou".into());
            }
            Ok(Contexto(ctx))
        }

        /// Todos os certificados do repositório (cada um com o próprio contexto duplicado).
        fn todos(&self) -> Vec<Contexto> {
            let mut lista = Vec::new();
            let mut anterior: *const CERT_CONTEXT = null();
            loop {
                let atual = unsafe { CertEnumCertificatesInStore(self.0, anterior) };
                if atual.is_null() {
                    break;
                }
                lista.push(Contexto(unsafe { CertDuplicateCertificateContext(atual) }));
                anterior = atual;
            }
            lista
        }
    }

    impl Drop for Repositorio {
        fn drop(&mut self) {
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    struct Contexto(*const CERT_CONTEXT);

    impl Drop for Contexto {
        fn drop(&mut self) {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct VinculoAnterior {
        provedor: String,
        container: String,
        tipo_provedor: u32,
        flags: u32,
        key_spec: u32,
    }

    impl Contexto {
        fn der(&self) -> Vec<u8> {
            let c = unsafe { &*self.0 };
            unsafe { std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize) }.to_vec()
        }

        fn nome(&self) -> String {
            let mut buffer = [0u16; 256];
            let len = unsafe {
                CertGetNameStringW(self.0, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), buffer.as_mut_ptr(), buffer.len() as u32)
            };
            String::from_utf16_lossy(&buffer[..len.saturating_sub(1) as usize])
        }

        fn vinculo(&self) -> Option<VinculoAnterior> {
            let mut tamanho = 0u32;
            if unsafe { CertGetCertificateContextProperty(self.0, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut tamanho) } == 0 {
                return None;
            }
            // u64 para garantir o alinhamento dos ponteiros dentro da estrutura.
            let mut buffer = vec![0u64; (tamanho as usize).div_ceil(8)];
            let ok = unsafe {
                CertGetCertificateContextProperty(self.0, CERT_KEY_PROV_INFO_PROP_ID, buffer.as_mut_ptr() as *mut c_void, &mut tamanho)
            };
            if ok == 0 {
                return None;
            }
            let info = unsafe { &*(buffer.as_ptr() as *const CRYPT_KEY_PROV_INFO) };
            Some(VinculoAnterior {
                provedor: unsafe { de_wide(info.pwszProvName) },
                container: unsafe { de_wide(info.pwszContainerName) },
                tipo_provedor: info.dwProvType,
                flags: info.dwFlags,
                key_spec: info.dwKeySpec,
            })
        }

        fn vincular(&self, provedor: &str, container: &str, tipo: u32, flags: u32, key_spec: u32) -> Resultado {
            let mut provedor = w(provedor);
            let mut container = w(container);
            let info = CRYPT_KEY_PROV_INFO {
                pwszContainerName: container.as_mut_ptr(),
                pwszProvName: provedor.as_mut_ptr(),
                dwProvType: tipo,
                dwFlags: flags,
                cProvParam: 0,
                rgProvParam: null_mut(),
                dwKeySpec: key_spec,
            };
            let ok = unsafe {
                CertSetCertificateContextProperty(self.0, CERT_KEY_PROV_INFO_PROP_ID, 0, &info as *const _ as *const c_void)
            };
            if ok == 0 {
                return Err("CertSetCertificateContextProperty falhou".into());
            }
            Ok(())
        }
    }

    fn pasta_de_backup() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(base).join("MyCert").join("ksp-vinculos-anteriores")
    }

    fn eh_autoassinado(der: &[u8]) -> bool {
        use x509_cert::der::Decode;
        x509_cert::Certificate::from_der(der)
            .map(|c| c.tbs_certificate.subject == c.tbs_certificate.issuer)
            .unwrap_or(false)
    }

    pub fn importar(substituir: bool) -> Resultado {
        let certificados = Broker::from_env()
            .certificates()
            .map_err(|e| format!("não consegui falar com o app MyCert (ele está aberto?): {e}"))?;
        if certificados.is_empty() {
            return Err("o app MyCert não tem nenhum certificado configurado".into());
        }
        let meus = Repositorio::abrir("MY")?;
        let intermediarias = Repositorio::abrir("CA")?;
        for wire in certificados {
            let der = STANDARD.decode(wire.der_b64.trim()).map_err(|e| format!("der_b64 inválido em '{}': {e}", wire.id))?;
            let thumb = thumbprint(&der);
            let container = key_name_for(&thumb);

            if let Some(existente) = meus.buscar(&thumb)
                && let Some(anterior) = existente.vinculo()
                && anterior.provedor != PROVIDER_NAME
            {
                if !substituir {
                    println!(
                        "PULADO  {} ({}): já vinculado a \"{}\". O repositório guarda um provedor por \
                         certificado; use --substituir para trocar (o vínculo atual é guardado e volta com `remover`).",
                        existente.nome(),
                        hex(&thumb).to_uppercase(),
                        anterior.provedor
                    );
                    continue;
                }
                std::fs::create_dir_all(pasta_de_backup()).map_err(|e| e.to_string())?;
                let arquivo = pasta_de_backup().join(format!("{}.json", hex(&thumb)));
                std::fs::write(&arquivo, serde_json::to_vec_pretty(&anterior).unwrap()).map_err(|e| e.to_string())?;
                println!("Vínculo anterior (\"{}\") guardado em {}", anterior.provedor, arquivo.display());
            }

            let contexto = meus.adicionar(&der)?;
            // KeySpec 0 e tipo 0 = chave CNG, igual ao que o SafeID grava.
            contexto.vincular(PROVIDER_NAME, &container, 0, 0, 0)?;
            println!("VINCULADO  {} ({}) -> {container}", contexto.nome(), hex(&thumb).to_uppercase());

            for elo in &wire.chain_der_b64 {
                let Ok(der) = STANDARD.decode(elo.trim()) else { continue };
                // A raiz não entra: confiar numa AC raiz é decisão do usuário/da política,
                // não de um instalador. As intermediárias só ajudam a montar a cadeia.
                if !eh_autoassinado(&der) {
                    intermediarias.adicionar(&der)?;
                }
            }
        }
        Ok(())
    }

    fn vinculados(repositorio: &Repositorio) -> Vec<(Contexto, VinculoAnterior)> {
        repositorio
            .todos()
            .into_iter()
            .filter_map(|c| {
                let v = c.vinculo()?;
                (v.provedor == PROVIDER_NAME).then_some((c, v))
            })
            .collect()
    }

    pub fn remover() -> Resultado {
        let meus = Repositorio::abrir("MY")?;
        let lista = vinculados(&meus);
        if lista.is_empty() {
            println!("Nenhum certificado vinculado ao MyCert.");
        }
        for (contexto, _) in lista {
            let thumb = thumbprint(&contexto.der());
            let arquivo = pasta_de_backup().join(format!("{}.json", hex(&thumb)));
            if let Ok(conteudo) = std::fs::read(&arquivo) {
                let anterior: VinculoAnterior = serde_json::from_slice(&conteudo).map_err(|e| e.to_string())?;
                contexto.vincular(&anterior.provedor, &anterior.container, anterior.tipo_provedor, anterior.flags, anterior.key_spec)?;
                let _ = std::fs::remove_file(&arquivo);
                println!("RESTAURADO  {} -> \"{}\"", contexto.nome(), anterior.provedor);
            } else {
                // Sem vínculo anterior: fomos nós que colocamos o certificado aqui.
                let nome = contexto.nome();
                let duplicado = unsafe { CertDuplicateCertificateContext(contexto.0) };
                if unsafe { CertDeleteCertificateFromStore(duplicado) } == 0 {
                    return Err(format!("não foi possível remover {nome}"));
                }
                println!("REMOVIDO  {nome}");
            }
        }
        Ok(())
    }

    pub fn listar() -> Resultado<Vec<(String, String, Vec<u8>)>> {
        let meus = Repositorio::abrir("MY")?;
        let lista: Vec<_> = vinculados(&meus).into_iter().map(|(c, v)| (c.nome(), v.container, c.der())).collect();
        if lista.is_empty() {
            println!("Nenhum certificado vinculado ao MyCert. Rode `importar` com o app aberto.");
        }
        for (nome, container, _) in &lista {
            println!("{nome}\n    chave: {container}");
        }
        Ok(lista)
    }

    // -----------------------------------------------------------------------------------
    // Teste de ponta a ponta pelo NCrypt
    // -----------------------------------------------------------------------------------

    /// Passa pelo mesmo caminho de um navegador: NCryptOpenStorageProvider carrega a DLL
    /// registrada em System32, NCryptOpenKey abre a chave pelo nome gravado no
    /// certificado e NCryptSignHash chega ao broker. A assinatura é conferida aqui com a
    /// chave pública do certificado — se o provedor devolvesse lixo, o teste acusaria.
    pub fn testar(pss: bool) -> Resultado {
        let lista = listar()?;
        if lista.is_empty() {
            return Err("nada para testar".into());
        }
        let mut provedor: NCRYPT_PROV_HANDLE = 0;
        let nome = w(PROVIDER_NAME);
        let status = unsafe { NCryptOpenStorageProvider(&mut provedor, nome.as_ptr(), 0) };
        if status != 0 {
            return Err(format!("NCryptOpenStorageProvider falhou (0x{:08X}); o provedor está instalado?", status as u32));
        }
        let mut falhas = 0;
        for (nome_cert, container, der) in lista {
            println!("\n{nome_cert}");
            let publica = RsaPublic::from_certificate(&der).ok_or("chave pública não é RSA")?;
            let chave_publica = RsaPublicKey::new(BigUint::from_bytes_be(&publica.modulus), BigUint::from_bytes_be(&publica.exponent))
                .map_err(|e| e.to_string())?;
            let mut chave: NCRYPT_KEY_HANDLE = 0;
            let nome_chave = w(&container);
            let status = unsafe { NCryptOpenKey(provedor, &mut chave, nome_chave.as_ptr(), 0, 0) };
            if status != 0 {
                println!("  NCryptOpenKey falhou (0x{:08X})", status as u32);
                falhas += 1;
                continue;
            }
            let hash = Sha256::digest(b"MyCert KSP - teste de assinatura");
            let algoritmo = w("SHA256");
            let mut modos = vec!["PKCS#1"];
            if pss {
                modos.push("PSS");
            }
            for modo in modos {
                let pkcs1 = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: algoritmo.as_ptr() };
                let pss_info = BCRYPT_PSS_PADDING_INFO { pszAlgId: algoritmo.as_ptr(), cbSalt: 32 };
                let (padding, flags) = if modo == "PSS" {
                    (&pss_info as *const _ as *const c_void, NCRYPT_PAD_PSS_FLAG)
                } else {
                    (&pkcs1 as *const _ as *const c_void, NCRYPT_PAD_PKCS1_FLAG)
                };
                let inicio = std::time::Instant::now();
                let mut tamanho = 0u32;
                let mut status =
                    unsafe { NCryptSignHash(chave, padding, hash.as_ptr(), 32, null_mut(), 0, &mut tamanho, flags) };
                let mut assinatura = vec![0u8; tamanho as usize];
                if status == 0 {
                    status = unsafe {
                        NCryptSignHash(chave, padding, hash.as_ptr(), 32, assinatura.as_mut_ptr(), tamanho, &mut tamanho, flags)
                    };
                }
                // NTE_NOT_SUPPORTED em PSS é a resposta correta: a API do provedor só
                // assina PKCS#1 e o KSP recusa o PSS sem ir à rede.
                if modo == "PSS" && status as u32 == 0x8009_0029 {
                    println!("  PSS: não suportado (esperado — a API do provedor só assina PKCS#1)");
                    continue;
                }
                if status != 0 {
                    println!("  {modo}: NCryptSignHash falhou (0x{:08X}) — detalhes no MYCERT_PKCS11_LOG", status as u32);
                    falhas += 1;
                    continue;
                }
                assinatura.truncate(tamanho as usize);
                let conferida = if modo == "PSS" {
                    chave_publica.verify(Pss::new::<Sha256>(), &hash, &assinatura)
                } else {
                    chave_publica.verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &assinatura)
                };
                match conferida {
                    Ok(()) => println!("  {modo}: OK — assinatura de {} bytes conferida em {:?}", assinatura.len(), inicio.elapsed()),
                    Err(e) => {
                        println!("  {modo}: assinatura NÃO confere com o certificado ({e})");
                        falhas += 1;
                    }
                }
            }
            unsafe { NCryptFreeObject(chave) };
        }
        unsafe { NCryptFreeObject(provedor) };
        if falhas > 0 { Err(format!("{falhas} teste(s) falharam")) } else { Ok(()) }
    }
}
