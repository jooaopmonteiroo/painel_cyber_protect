# 🛡️ JM CYBER PROTECT — DOCUMENTAÇÃO TÉCNICA E ANALÍTICA DE PLANOS DE SEGURANÇA

> **Documento Oficial de Engenharia e Governança de Cibersegurança**  
> **Organização:** JM Distribuição & Transportes  
> **Plataforma:** Acronis Cyber Protect Cloud (Enterprise Edition)  
> **Data de Atualização:** Outubro / 2026  
> **Classificação da Informação:** Uso Interno / Técnico & Auditoria  

---

## 📑 SUMÁRIO EXECUTIVO

Este documento estabelece o referencial técnico, operacional e analítico de todas as **17 Políticas de Proteção e Segurança** configuradas e ativas no ecossistema do **JM Cyber Protect**. 

A arquitetura de segurança da informação da JM Distribuição está alicerçada no paradigma de **Defesa em Profundidade (*Defense-in-Depth*)**, integrando proteção preditiva (*pre-execution*), preventiva (*in-execution*), reativa (*post-execution / EDR*) e de continuidade de negócios (*disaster recovery & backup*).

### 📊 Visão Geral do Parque de Proteção

| Indicador | Quantidade Consolidada |
| :--- | :--- |
| **Total de Planos de Proteção Ativos** | **17 Políticas Corporativas Especializadas** |
| **Cargas de Trabalho e Contas Monitoradas** | **790 Alvos / Dispositivos / Caixas M365** |
| **Dispositivos Físicos e Virtuais Mapeados** | **683 Recursos (Servidores, Estações, Laptops, VMs)** |
| **Agentes Acronis Conectados** | **172 Agentes Dedicados com Telemetria em Tempo Real** |
| **Cobertura de Backup em Nuvem** | **Nuvem Criptografada Acronis Tier-IV (AES-256)** |

---

## ⚙️ DICIONÁRIO FUNCIONAL DOS MÓDULOS DE PROTEÇÃO

Antes da análise individual de cada política, definem-se as capacidades tecnológicas e a finalidade de cada motor de proteção ativo no agente unificado Acronis:

### 1. Active Protection (Acronis Heuristic Anti-Ransomware)
* **Como Funciona:** Motor heurístico impulsionado por inteligência artificial que monitora o comportamento de processos no espaço de usuário e kernel em tempo real. Identifica padrões característicos de criptografia não autorizada de arquivos, alteração do *Master Boot Record* (MBR) ou destruição de cópias de sombra (*Volume Shadow Copies - VSS*).
* **Finalidade Prática:** Interrupção imediata de processos cripto-maliciosos (*kill-process*) e reversão instantânea (*rollback*) de quaisquer arquivos modificados a partir de um cache seguro de memória volátil.
* **Justificativa de Segurança:** Mitigação de ameaças de dia zero (*zero-day*) que burlam assinaturas estáticas de antivírus convencionais.

### 2. Antimalware Protection em Tempo Real (NGAV)
* **Como Funciona:** Antivírus de próxima geração de camada dupla, combinando análise estática por assinaturas em nuvem de baixa latência com motores dinâmicos de detecção comportamental e proteção de memória.
* **Finalidade Prática:** Varredura em tempo real em todas as operações de I/O de disco (criação, modificação, execução de arquivos), além de varreduras agendadas de integridade do sistema.
* **Justificativa de Segurança:** Prevenção de infiltração de cavalos de Troia, spyware, worms, scripts PowerShell ofuscados e malwares direcionados à infraestrutura de faturamento e logística.

### 3. Endpoint Detection and Response (EDR)
* **Como Funciona:** Coletor contínuo de eventos do sistema operacional (criação de processos, conexões de socket de rede, injeção de DLLs, modificações no registro do Windows). Mapeia cada alerta à taxonomia internacional **MITRE ATT&CK**.
* **Finalidade Prática:** Visibilidade forense fim-a-fim da cadeia de ataque (*attack chain*), permitindo aos analistas investigar a causa-raiz (*root cause*), conter o host da rede (*network containment*), isolar arquivos e finalizar processos ramificados.
* **Justificativa de Segurança:** Detecção precoce de invasores humanos (*hands-on-keyboard*) e ataques *living-off-the-land* que utilizam ferramentas nativas do sistema (como WMI, certutil, bitsadmin).

### 4. Gestão de Patches (Patch Management)
* **Como Funciona:** Mecanismo centralizado de auditoria e aplicação de correções de segurança para o sistema operacional Windows e para mais de 300 aplicações de terceiros (navegadores Chrome/Edge, Java, Adobe, 7-Zip, AnyDesk).
* **Finalidade Prática:** Download automatizado, teste de integridade e instalação das atualizações críticas fora do horário de pico, com pré-criação de ponto de restauração de segurança.
* **Justificativa de Segurança:** Fechamento sistemático de vulnerabilidades conhecidas (CVEs com pontuação CVSS elevada) que servem de porta de entrada para vetores de movimentação lateral e elevação de privilégios.

### 5. Avaliação Contínua de Vulnerabilidades (Vulnerability Assessment)
* **Como Funciona:** Scanner leve em segundo plano que cataloga versões de binários e bibliotecas no endpoint e correlaciona com o banco global de vulnerabilidades da Acronis e NVD (National Vulnerability Database).
* **Finalidade Prática:** Mapeamento proativo do nível de exposição de cada estação e priorização de risco por criticidade (Baixo, Médio, Alto, Crítico).
* **Justificativa de Segurança:** Prover ao time de TI inteligência acionável sobre quais sistemas requerem mitigação imediata mesmo antes do lançamento de um patch oficial.

### 6. Filtro de Conteúdo Web (URL Filtering & Anti-Phishing)
* **Como Funciona:** Driver de inspeção de tráfego de rede HTTP/HTTPS no nível de camada de transporte (Winsock/WFP). Bloqueia requisições a endereços IP e domínios categorizados como maliciosos, servidores de Comando e Controle (C2), ou páginas de phishing.
* **Finalidade Prática:** Interrupção imediata de tentativas de navegação a sites de golpe, bloqueio de downloads de payloads maliciosos e proteção contra roubo de credenciais via páginas falsas de login.
* **Justificativa de Segurança:** O e-mail e a navegação web respondem por mais de 85% dos vetores iniciais de comprometimento em redes corporativas.

### 7. Varredura Antimalware de Backups (Backups Scanning)
* **Como Funciona:** O storage em nuvem Acronis escaneia automaticamente o conteúdo das imagens de backup recém-geradas com o motor antimalware central antes de consolidar o ponto de recuperação.
* **Finalidade Prática:** Garantir que backups armazenados não contenham malware dormente (*dormant threats*).
* **Justificativa de Segurança:** Previne o cenário catastrófico de "ciclo de reinfeção" (*reinfection loop*), no qual uma empresa restaura um servidor após um ataque e reinstala o mesmo backdoor que causou a invasão.

### 8. Proteção para IA Generativa (Generative AI Protection)
* **Como Funciona:** Monitoramento e regras de controle sobre aplicações de inteligência artificial generativa baseadas na web (ChatGPT, Claude, Copilot, etc.).
* **Finalidade Prática:** Prevenção de vazamento de dados (*Data Leak Prevention - DLP*), impedindo que dados cadastrais de clientes, relatórios fiscais ou credenciais sejam colados em prompts de IA pública.
* **Justificativa de Segurança:** Conformidade estrita com a **LGPD** e mitigação do risco de exposição inadvertida de segredos comerciais da operação de transportes.

### 9. Integração com Windows Defender (Defender Management)
* **Como Funciona:** Gerenciamento centralizado das políticas nativas do Windows Defender pelo console Acronis, orquestrando exclusões e quarentenas para evitar conflito de kernel (*filter driver collisions*).
* **Finalidade Prática:** Atuação coordenada onde o Acronis potencializa o Defender ou assume o papel primário de antivírus sem degradação de performance.
* **Justificativa de Segurança:** Garantia de que a proteção nativa do sistema operacional nunca seja desativada acidentalmente por malware ou por usuários com privilégios locais.

### 10. Mapa de Proteção de Dados (Data Protection Map)
* **Como Funciona:** Mecanismo de auditoria de armazenamento que analisa discos rígidos locais para identificar extensões de dados críticos (.docx, .xlsx, .pdf, bancos de dados, arquivos de emissão fiscal).
* **Finalidade Prática:** Verificação se os arquivos descobertos estão incluídos nas rotinas de backup configuradas.
* **Justificativa de Segurança:** Eliminação de "pontos cegos" de dados onde um operador salva documentos sensíveis da empresa fora dos diretórios padrão de backup.

### 11. Sincronização em Nuvem & Backup Contínuo (Cloud Storage Sync)
* **Como Funciona:** Replicação síncrona/contínua de alterações em arquivos vitais diretamente para armazenamento redundante em nuvem criptografado.
* **Finalidade Prática:** Recuperação com perda de dados praticamente nula (*RPO - Recovery Point Objective próximo a zero*).
* **Justificativa de Segurança:** Proteção em tempo real de logs de segurança, arquivos de auditoria e bases transacionais operacionais.

---

## 🏛️ MATRIZ ANALÍTICA DAS 17 POLÍTICAS DE PROTEÇÃO

Abaixo está o detalhamento de cada uma das 17 políticas de segurança ativas no tenant da JM Distribuição:

---

### [01] POLÍTICA: Backup Contas 365
* **Escopo e Alvos:** **453 contas e caixas de correio do Microsoft 365** da JM Distribuição (Exchange Online, OneDrive for Business, SharePoint Online e Microsoft Teams).
* **Módulos Ativos:**
  - *Cloud-to-Cloud Backup M365*
  - *Active Protection & Antimalware*
  - *Backups Scanning no Storage Nuvem*
  - *Data Protection Map*
  - *Endpoint Detection and Response (EDR)*
  - *Generative AI Protection*
  - *Microsoft Security Essentials & Windows Defender Management*
  - *Patch Management & Vulnerability Assessment*
  - *URL Filtering*
* **Finalidade Prática ("Para que serve"):**
  Realiza o backup automático diário de todas as caixas postais corporativas, mensagens trocadas, anexos, repositórios de arquivos do OneDrive e sites do SharePoint de toda a diretoria, operação e colaboradores da empresa.
* **Justificativa de Segurança ("Por que está ativo"):**
  O modelo de responsabilidade compartilhada da Microsoft (*Shared Responsibility Model*) estipula expressamente que a responsabilidade pela integridade, retenção histórica e recuperação dos dados corporativos é do cliente, não da Microsoft. Essa política protege a JM contra exclusões acidentais, ataques de *business email compromise* (BEC), sequestro de caixas postais e atende às exigências de guarda documental fiscal e conformidade da **LGPD**.

---

### [02] POLÍTICA: Acesso Remoto JM
* **Escopo e Alvos:** **167 estações de trabalho móveis, laptops de colaboradores em regime híbrido/home office e conexões de suporte técnico externo**.
* **Módulos Ativos:**
  - *Acronis Active Protection (Anti-Ransomware Heurístico)*
  - *Backup Contínuo de Arquivos de Trabalho*
  - *Cloud Storage Sync Criptografado*
* **Finalidade Prática ("Para que serve"):**
  Protege terminais que operam frequentemente fora do perímetro da rede local da empresa (utilizando conexões de internet domésticas, Wi-Fi público ou conexões 4G/5G). Sincroniza continuamente arquivos de trabalho vitais diretamente para a nuvem segura.
* **Justificativa de Segurança ("Por que está ativo"):**
  Endpoints remotos estão mais suscetíveis a ataques de força bruta contra portas de RDP (Remote Desktop Protocol), tentativas de interceptação de tráfego e infecções por malware doméstico. A presença do Active Protection impede que malwares criptografem os discos locais mesmo se a máquina estiver desconectada da VPN corporativa.

---

### [03] POLÍTICA: Protect JM
* **Escopo e Alvos:** **85 estações de trabalho físicas da Matriz / Sede Administrativa** da JM Distribuição.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect:* Active Protection, Antimalware em Tempo Real, EDR Avançado, Gestão de Patches, Avaliação de Vulnerabilidades, Filtro de Conteúdo Web, Proteção GenAI, Varredura de Backups e Integração Windows Defender.
* **Finalidade Prática ("Para que serve"):**
  Constitui a linha de defesa principal do parque computacional da sede, controlando navegação web, impedindo execução de softwares não homologados, corrigindo brechas do Windows e de navegadores e monitorando o comportamento de cada estação via EDR.
* **Justificativa de Segurança ("Por que está ativo"):**
  A sede concentra o maior volume de usuários com acesso simultâneo a sistemas de gestão ERP, pastas compartilhadas na rede local e impressoras fiscais. Uma infecção nessa rede local causaria contaminação horizontal imediata. A suíte completa garante isolamento em caso de incidente e fechamento sistemático de brechas.

---

### [04] POLÍTICA: Protect Line Haul
* **Escopo e Alvos:** **22 terminais operacionais dedicados à gestão de transporte de linha longa (*Line Haul* / Transferência Interestadual)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Garante a disponibilidade ininterrupta dos computadores que controlam as viagens interestaduais de caminhões, alocação de cargas pesadas em rotas de longa distância e sincronização com centros de distribuição parceiros.
* **Justificativa de Segurança ("Por que está ativo"):**
  A interrupção de um terminal de Line Haul paralisa o carregamento e despacho de carretas, gerando multas por atraso de entrega e gargalos em toda a cadeia de suprimentos. O plano prioriza alta resiliência e bloqueio a ransomwares.

---

### [05] POLÍTICA: Protect Last Mile
* **Escopo e Alvos:** **12 terminais de expedição, roteirização urbana e entrega final (*Last Mile*)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege as máquinas responsáveis pelo despacho diário de frotas urbanas, conferência de entregas, comunicação com motoristas de vans/VUCs e leitura de canhotos de entrega digitais.
* **Justificativa de Segurança ("Por que está ativo"):**
  O *Last Mile* é a etapa mais dinâmica e visível ao cliente final. Falhas operacionais decorrentes de infecções cibernéticas impedem a conclusão de entregas agendadas no mesmo dia (*same-day delivery*), causando prejuízo financeiro e danos diretos à reputação da marca.

---

### [06] POLÍTICA: Protect First Mile
* **Escopo e Alvos:** **10 terminais de recepção, coleta e triagem inicial de encomendas e cargas (*First Mile*)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Assegura o funcionamento estável dos computadores que realizam a entrada de mercadorias no armazém, pesagem, cubagem e geração inicial de etiquetas de rastreamento.
* **Justificativa de Segurança ("Por que está ativo"):**
  Se a triagem inicial parar, caminhões de coleta ficam parados no pátio gerando filas e impossibilitando o processamento do fluxo logístico de entrada. O plano impede paradas não programadas por falhas de sistema ou contaminações por pendrives de transportadores terceiros.

---

### [07] POLÍTICA: Protect GRIS
* **Escopo e Alvos:** **9 terminais de alta criticidade da Central de Gerenciamento de Risco e Segurança Patrimonial (GRIS)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege os computadores que operam sistemas de rastreamento via satélite de veículos, monitoramento de rotas de risco, controle de portas de baú, sensores de desengate e acionamento de escolta armada / pronta resposta policial.
* **Justificativa de Segurança ("Por que está ativo"):**
  **Criticidade Máxima.** Um ataque cibernético bem-sucedido contra a central de GRIS poderia permitir que organizações criminosas cegassem o rastreamento de caminhões com cargas de altíssimo valor (eletrônicos, farmacêuticos) ou desativassem travas de segurança remotamente. A suíte completa com EDR e isolamento é obrigatória por apólices de seguro de carga.

---

### [08] POLÍTICA: Protect TI
* **Escopo e Alvos:** **7 estações de trabalho da equipe de Tecnologia da Informação, Desenvolvedores e Administradores de Infraestrutura**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Monitora e protege máquinas onde são manipuladas senhas mestras, chaves SSH, repositórios de código-fonte, acessos a roteadores, firewalls e painéis administrativos de nuvem.
* **Justificativa de Segurança ("Por que está ativo"):**
  Estações de profissionais de TI são alvos preferenciais de atacantes em técnicas de *lateral movement* e *credential dumping*. O EDR ativo registra e bloqueia qualquer tentativa de execução de ferramentas de extração de credenciais (Mimikatz, Procdump, etc.).

---

### [09] POLÍTICA: Protect Qualidade
* **Escopo e Alvos:** **6 terminais do departamento de Controle de Qualidade, Compliance e Auditoria de Processos**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege planilhas, dashboards de indicadores de serviço (SLA), relatórios de avarias e documentação de certificações ISO e exigências de clientes contratuais.
* **Justificativa de Segurança ("Por que está ativo"):**
  Preserva a integridade e confidencialidade dos dados de auditoria, prevenindo fraudes internas e perda de histórico de performance operacional.

---

### [10] POLÍTICA: Protect Emissões
* **Escopo e Alvos:** **6 computadores dedicados à Emissão Fiscal e Faturamento (Conhecimento de Transporte Eletrônico - CT-e, Manifesto MDF-e e Notas Fiscais NF-e)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Garante o funcionamento e integridade dos softwares emissores fiscais, comunicação contínua com os servidores da SEFAZ (Secretaria da Fazenda) e guarda segura dos certificados digitais corporativos (A1/A3).
* **Justificativa de Segurança ("Por que está ativo"):**
  Nenhum veículo de carga pode circular em rodovias sem CT-e e MDF-e devidamente autorizados pela SEFAZ, sob pena de retenção do veículo e pesadas multas fiscais. Além disso, a política protege o certificado digital corporativo contra roubo ou exportação não autorizada.

---

### [11] POLÍTICA: Protect Frota
* **Escopo e Alvos:** **4 terminais da Gestão de Frota, Oficinas Mecânicas e Abastecimento de Veículos**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege o controle de manutenção preventiva dos caminhões, troca de pneus, registros de tacógrafo, abastecimento e histórico de motoristas.
* **Justificativa de Segurança ("Por que está ativo"):**
  Ambientes de oficina frequentemente utilizam computadores compartilhados entre diversos funcionários operacionais. O filtro web rigoroso e o antimalware evitam contaminações oportunistas enquanto o backup garante a persistência dos registros mecânicos.

---

### [12] POLÍTICA: Protect Financeiro
* **Escopo e Alvos:** **4 terminais do departamento Financeiro, Contas a Pagar/Receber, Tesouraria e Conciliação Bancária**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege acessos a internet banking, plataformas de pagamento de fretes (CIOT, pagamentos eletrônicos de pedágio), ERP financeiro e geração de remessas/retornos bancários (CNAB).
* **Justificativa de Segurança ("Por que está ativo"):**
  Alvo de altíssimo risco para malwares bancários (*banking trojans*), ataques de substituição de boletos (*Man-in-the-Browser*) e golpes de spear-phishing. O filtro web bloqueia URLs maliciosas e o EDR detecta qualquer tentativa de injeção de processos em navegadores.

---

### [13] POLÍTICA: SIEM JM TRANSPORTES
* **Escopo e Alvos:** **1 servidor centralizado de Coleta de Logs, Telemetria de Segurança e Auditoria de Eventos da JM**.
* **Módulos Ativos:**
  - *Acronis Active Protection*
  - *Backup Contínuo de Arquivos de Log e Eventos*
  - *Cloud Storage Sync Criptografado*
* **Finalidade Prática ("Para que serve"):**
  Armazena e correlaciona trilhas de auditoria, eventos de login, logs de firewall e registros de acesso a servidores. Replica continuamente os registros para a nuvem segura.
* **Justificativa de Segurança ("Por que está ativo"):**
  Atacantes qualificados tentam destruir ou limpar logs de eventos (*log tampering*) para ocultar seus rastros durante uma invasão. A sincronização contínua com a nuvem garante a imutabilidade das evidências para perícia forense e conformidade regulatória.

---

### [14] POLÍTICA: Protect Server
* **Escopo e Alvos:** **1 servidor principal de Infraestrutura Core da JM Distribuição**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege o servidor central que hospeda serviços internos essenciais, bases de dados corporativas e compartilhamento de arquivos de rede.
* **Justificativa de Segurança ("Por que está ativo"):**
  A indisponibilidade deste servidor afeta simultaneamente todos os setores da empresa. O plano aplica proteções em camada com restrição máxima de execução e backup automatizado de integridade de sistema (*bare-metal restore*).

---

### [15] POLÍTICA: Protect RH
* **Escopo e Alvos:** **1 estação de trabalho da Gestão de Recursos Humanos e Pessoal**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Protege dados pessoais de funcionários (fichas cadastrais, contratos de trabalho, atestados médicos, folha de pagamento, documentos de admissão e demissão).
* **Justificativa de Segurança ("Por que está ativo"):**
  Conformidade direta com a **LGPD (Lei Geral de Proteção de Dados)**. O vazamento ou acesso indevido a dados sensíveis de colaboradores sujeita a empresa a severas sanções da ANPD e ações trabalhistas. A proteção do endpoint e a criptografia dos backups garantem a confidencialidade e guarda dos dados.

---

### [16] POLÍTICA: Protect Quarentena
* **Escopo e Alvos:** **1 máquina de isolamento e análise técnica (*Sandbox / Quarantine Station*)**.
* **Módulos Ativos:**
  - *Suíte Completa Acronis Cyber Protect (NGAV + EDR + Patch + URL Filter + Backup)*
* **Finalidade Prática ("Para que serve"):**
  Ambiente controlado utilizado pelo time de cibersegurança para isolar estações suspeitas de infecção, testar anexos duvidosos recebidos por e-mail e executar amostras para validação de falso-positivo.
* **Justificativa de Segurança ("Por que está ativo"):**
  Permite conter e investigar ameaças em ambiente estéril sem colocar em risco a rede corporativa de produção.

---

### [17] POLÍTICA: Plano de integração - jm.corp
* **Escopo e Alvos:** **1 nó de integração de domínio de rede local (*Active Directory / jm.corp*)**.
* **Módulos Ativos:**
  - *Acronis Active Protection*
  - *Backup Contínuo de Serviços de Diretório*
  - *Cloud Storage Sync Criptografado*
* **Finalidade Prática ("Para que serve"):**
  Sincroniza e garante a cópia de segurança contínua da base de dados do Active Directory (NTDS.dit), políticas de grupo (GPOs) e zonas de DNS corporativo.
* **Justificativa de Segurança ("Por que está ativo"):**
  O controlador de domínio é a "chave-mestra" da rede. Caso ocorra corrupção do banco do AD ou ataque de ransomware que afete o domínio, o backup contínuo permite a restauração limpa da infraestrutura de autenticação sem necessidade de recriação manual de centenas de usuários.

---

## 🔒 MATRIZ DE CONFORMIDADE E DIRETRIZES DE RISCO

| Framework / Norma | Requisito Atendido | Módulos Acronis Correspondentes |
| :--- | :--- | :--- |
| **NIST CSF (Protect / PR.AC)** | Gestão de Acessos e Proteção contra Malware | Antimalware NGAV, EDR, Integração Windows Defender |
| **NIST CSF (Protect / PR.IP)** | Gerenciamento de Vulnerabilidades e Patches | Patch Management, Vulnerability Assessment |
| **NIST CSF (Protect / PR.DS)** | Criptografia e Backup de Dados | Backup M365, Cloud Storage Sync, Data Protection Map |
| **NIST CSF (Detect / DE.CM)** | Monitoramento Contínuo da Rede e Endpoints | EDR com mapeamento MITRE ATT&CK, URL Filtering |
| **NIST CSF (Recover / RC.RP)** | Recuperação de Desastres e Resiliência | Varredura de Backups, Rollback Heurístico Active Protection |
| **LGPD (Art. 46)** | Medidas de Segurança para Proteção de Dados | Criptografia AES-256 em trânsito/repouso, Proteção GenAI |
| **ISO 27001 (A.12.2)** | Proteção contra Códigos Maliciosos | Active Protection Heurístico em Tempo Real |

---

## 📋 RECOMENDAÇÕES OPERACIONAIS PARA ADMINISTRAÇÃO

1. **Tratamento de Alertas e Avisos:**
   - As políticas com maior incidência de avisos (*Backup Contas 365* e *Protect JM*) devem ser acompanhadas semanalmente para verificar permissões de caixas postais M365 e reinicializações pendentes de máquinas após aplicação de patches.
2. **Revisão Periódica de Exclusões:**
   - Garantir que binários dos sistemas operacionais e fiscais de transporte (emissões de CT-e/MDF-e) permaneçam cadastrados nas exclusões de comportamento para evitar lentidão ou falsos positivos em fechamentos de mês.
3. **Teste Trimestral de Restauração (*Disaster Recovery Drill*):**
   - Executar testes controlados de recuperação de arquivos de amostra das políticas *Protect Server*, *Protect Emissões* e *Backup Contas 365* para validar o RTO (Recovery Time Objective) em caso de desastre real.
