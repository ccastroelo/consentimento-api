# Documentação da Arquitetura de Consentimento e Auditoria (PoC)

Esta documentação descreve a arquitetura da Prova de Conceito (PoC) para o sistema de gestão de consentimentos, focado no encadeamento de hashes (Hash Chaining), Event Sourcing e proteção à privacidade (LGPD - Direito ao Esquecimento).

## 1. Visão Geral

A arquitetura foi projetada para ser uma "Single-Stack" focada exclusivamente na lógica de auditoria forense e imutabilidade via PostgreSQL. Dispensamos o uso de barramentos de eventos externos (Redis) e cofres de chaves (Vault) para simplificar a topologia e focar no modelo acadêmico de integridade: a **Cadeia de Hashes (Hash Chain)**.

## 2. Arquitetura "Single-Stack" e Componentes

Todos os serviços são conteinerizados e orquestrados via `docker-compose.yml`:

- **Banco de Dados (PostgreSQL)**: Única fonte de verdade. Armazena tanto o estado operacional quanto o ledger imutável de auditoria.
- **Storage (MinIO)**: Armazena os documentos originais das políticas de privacidade (PDFs, HTMLs).
- **API de Políticas (`api-politicas`)**: Responsável por gerenciar os documentos de termos de uso e políticas de privacidade.
- **API de Consentimentos (`api-consentimentos`)**: Serviço núcleo. Recebe aceites/revogações, anonimiza os usuários em trânsito e encadeia criptograficamente cada evento no log de auditoria.
- **Worker de Privacidade (`api-worker`)**: Roda em background executando nativamente o Crypto-shredding lógico para titulares que exigiram o "Direito ao Esquecimento".
- **Painel Administrativo (`admin-panel`)** e **Mock IdP (`mock-idp`)**: Módulos de suporte para simulação visual e geração de tokens JWT autenticados.

## 3. Segurança Perimetral e API (Proteções e Autenticação)

A "api-consentimentos" é exposta seguindo os princípios de *Zero-Trust*, garantindo que identidades e autorizações sejam estritamente validadas. Existem dois decoradores atuando como *Middlewares* de proteção nas rotas:

### 3.1. Validação Criptográfica de Origem via Chave Simétrica (`@token_required`)
Esta camada serve os usuários finais (Titulares de Dados) garantindo proteção de *Zero-Trust* contra o cliente HTTP da requisição:

- **Autenticação Padrão:** Exige que qualquer criação de consentimento (`POST /consents`), consulta de histórico pessoal ou solicitação de esquecimento envie um token autenticado via header `Authorization: Bearer <TOKEN>`.
- **Prova de Origem Matemática (HS256):** Há uma correlação irrefutável entre o Provedor de Identidade (Mock IdP) e a API de Consentimentos. Ambos compactuam com uma única "Symmetric Key" ou "Secret" (`JWT_SECRET`). Como a API de Consensos repassa o token para o decodificador atrelado à chave privada, qualquer token forjado externamente resulta em Falha Criptográfica. A origem é atestada e assumida pela comprovação de posse do `Secret` compartilhado unicamente intra-cluster.
- **Validação Anti-Replay e Blindagem de PII:** Mesmo que a chave confira, a checagem das premissas JWT é dura: exige-se do emissor atestar o momento exato em que ele provou a identidade (`iat`), por quanto tempo ela é crível (`exp`) e expõe unicamente o `user_id`. Dessa forma, ataques de adulteração enviando `{ "user_id": X }` via JSON `body` não funcionam. As requisições sacam estritamente o `user_id` de dentro do invólucro inviolável.
### 3.2. Segurança e Isolamento dos Endpoints de Auditoria
A segurança para extração e auditoria dos dados foi modelada com base no conceito de *Ledgers Públicos vs. Rastreamento Privado*:

- **Auditoria Macro/Regulatória (Aberta by-design):** A rota de extração geral (`GET /consents/policy/<id>`) fica **desprotegida** de tokens de autenticação. Isso é possível e seguro porque a arquitetura é intrinsecamente pseudonimizada na base de dados de Consensos. O sistema expõe abertamente toda a trilha, os carimbos de tempo e as assinaturas blindadas (`subject_pseudonym`) para auditoria externa, sendo matematicamente impossível reverter o pseudônimo num ID ou nome sem ter o Salt individual, não incorrendo em quebra da LGPD.
- **Auditoria Privada/Backoffice (`@admin_token_required`):** A extração da linha do tempo individual (`GET /admin/consents/user/<id>`) requer um poder total, pois o input é o `user_id` original em texto claro. A API pega a Identidade, vasculha o KMS Criptográfico (`UserCrypto`) e converte no hash para resgatar os rastros. Isso quebra o anonimato na ponta requisitante. Para suprimir esse risco, ela se blinda via M2M (*Machine-to-Machine*), exigindo o selo intransferível `ADMIN_TOKEN`. Apenas microsserviços internos isolados do core, operados por perfis ultra-restritos (DPO via `admin-panel`), podem carimbar esta credencial.
## 4. Modelos de Segurança Intrínseca (Banco de Dados Central)

O núcleo da segurança intra-registro reside nos modelos SQLAlchemy (módulo `app.py`).

### 4.1. KMS Lógico (`UserCrypto`)
Esta tabela funciona como o "Cofre Mestre" e âncora da cadeia:
- **Salt Aleatório**: Cada usuário tem um `salt` exclusivo (`secrets.token_hex(32)`) gerado na primeira interação. Todos os registros de log usam um pseudônimo gerado via `HMAC-SHA256(user_id, salt)`.
- **Bloqueio Otimista (Concurrency)**: A coluna `version` mapeada no SQLAlchemy (`version_id_col`) atua como um semáforo rígido. Se duas transações tentarem gravar um consentimento simultaneamente para o mesmo usuário, uma transação falha, prevenindo bifurcações na linha temporal (forks).
- **Ponteiro da Cadeia (`last_consent_hash`)**: Aponta para o hash do registro mais recente do usuário.

### 4.2. Prova de Auditoria Imutável (`Consents`)
A tabela de consentimentos guarda os eventos.
- **Hash Chaining (`parent_hash`)**: Cada novo registro embute no seu cálculo o hash do registro anterior (`last_consent_hash` do usuário). Isso cria uma linha forense que impede modificações retroativas. O hash é calculado sobre: `pseudonym : id_policy : timestamp : channel : status : parent_hash`.
- **Snapshot de Ordenação (`sequence_version`)**: Copia a versão do `UserCrypto` no momento exato do aceite para garantir a prova de ordem (Audit Proof).
- **Hard Append-Only**: A tabela não sofre modificações. Qualquer "mudança de ideia" por parte do titular (ex: revogar acesso) acarreta em um *novo* registro que reajusta o status temporalmente, e não uma edição "in-place".

### 4.3. Imutabilidade Forçada (Mecanismo Append-Only)
Para garantir que a teoria do LEDGER não seja quebrada por conveniência na camada de domínio (ex: um desenvolvedor descuidado tentar forçar um `db.session.commit()` com um consentimento modificado ou apagado pela API), implementou-se uma trava dura no Motor de Mapeamento (ORM).

No núcleo da API usamos a feature de Eventos do SQLAlchemy para interceptar qualquer mutação na tabela `Consents`. Foram registrados dois `listeners`:
1. `before_update` (Antes de Atualizar)
2. `before_delete` (Antes de Deletar)

Caso qualquer transação dispare esses gatilhos, o sistema lança sumariamente um Erro Fatal (`Exception('Operação estritamente proibida: a tabela de auditoria é Append-Only')`), revertendo o *roll-back* na hora. Essa barreira blinda e atesta que não existem falhas de sofware que deixem o ledger corrompível sem ser barrado pelo código.

## 5. Direito ao Esquecimento (Event Sourcing & Crypto-shredding)

Deletar dados anonimizados quebrando correntes forenses não é viável. A arquitetura soluciona a LGPD preservando os logs:

1. **Deleção Diferida (Endpoint)**: A exclusão invocada pelo usuário na rota `DELETE /users/<id>/forget` apenas marca o usuário com a flag `pending_deletion = True` no banco de dados, sinalizando a intenção sem onerar o tempo de resposta da API (Non-blocking).
2. **Ciclo do Worker (`worker.py`)**: 
    - Um processo em background varre ativamente usuários com deleção pendente.
    - **Registro de Tombstone (A Lápide de Event Sourcing)**: A exclusão absoluta sem rastros quebraria a lógica do livro-razão (Ledger). Para manter a integridade temporal de *quando* o dado foi apagado e a mando de quem, o Worker insere ativamente um **novo registro final** na tabela de Consentimentos. Esse registro recebe o `status="forgotten"`, concatenando criptograficamente o hash do evento anterior à sua estrutura. Essa Lápide sela definitivamente a cadeia de eventos sob aquele pseudônimo.
    - **Crypto-shredding (O Apagão Físico)**: Na mesma fração de segundo que a Lápide é salva, o worker deleta fisicamente a linha geradora em `UserCrypto`. Ao apagar o `salt`, torna-se instantaneamente impossível processar o nome real originário daquela trilha cravada em log, preservando o "Direito ao Esquecimento" (privacidade perene) amparando uma auditoria imutável perante entidades fiscais (Transparência com Privacidade).

---

## 6. Schema de Banco de Dados Regulatório (PostgreSQL)

A orquestração do Event Sourcing apoia-se num schema relacional que isola entropia (salt) de trilhas (hashes).

### 6.1 Tabela `users_crypto` (O Cofre Lógico)
Gerencia o ciclo de vida criptográfico dos indivíduos. **Não possui ligações diretas por Foreign Key (FK)** com as tabelas operacionais para não travar o Crypto-Shredding por restrições de integridade.

| Coluna | Tipo | Descrição |
| :--- | :--- | :--- |
| `id_user` | Integer (PK) | Identificador real e isolado do usuário no sistema. |
| `salt` | String | Fator de entropia único (gerado em Hex32) para a criptografia HMAC. |
| `pending_deletion`| Boolean | Sinalizador de Soft-Delete capturado pelo ciclo do Worker. |
| `last_consent_hash`| String | **Ponteiro da Corrente (Cache):** Guarda o hash do último evento criado (a ponta da corrente). Quando um novo evento vai ser inserido, a API lê este campo rapidamente para engatar o novo hash, sem precisar fazer buscas lentas na tabela de Consents. |
| `version` | Integer | **Semáforo Contra Bifurcações (Optimistic Locking):** É um contador (`1, 2, 3...`). Se duas requisições simultâneas do mesmo usuário tentarem criar um evento ao mesmo tempo lendo a mesma versão "X", a primeira reescreve a versão para "Y" e a segunda falha instantaneamente com erro no banco. Isso impede que dois consentimentos apontem para o mesmo registro anterior, garantindo uma linha do tempo única e sem ramificações. |

### 6.2 Tabela `policies` (As Leis Básicas)
Armazena a trilha das políticas de privacidade que permeiam os consentimentos.

| Coluna | Tipo | Descrição |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Identificador único da Política. |
| `version` | String | Versão semântica (ex: "v1.2", "2024.1"). |
| `published_at` | Timestamp | Carimbo imutável de entrada em vigor. |
| `url` | Text | Ponteiro para o arquétipo em Storage (MinIO S3). |
| `hash` | String | SHA-256 do arquivo em disco (Garante que a política não foi alterada). |

### 6.3 Tabela `consents` (O Ledger Imutável)
O livro-razão blindado que grava transações de engajamento do indivíduo de forma linear. Protegida por ORM Listeners contra deções ou atualizações (Append-Only).

| Coluna | Tipo | Descrição |
| :--- | :--- | :--- |
| `id` | Integer (PK) | Auto-increment padrão. |
| `subject_pseudonym`| String (Index) | Assinatura irreversível (*HMAC(id_user, salt)*). Impede engenharia reversa. |
| `id_policy` | Integer (FK) | Vínculo dinâmico com regras de privacidade. Pode ser nulo p/ eventos de sistema (Tombstones). |
| `created_at` | Timestamp | Carimbo de entrada do Evento. |
| `channel` | String | Via de assinatura (ex: 'web', 'app', 'system'). |
| `validation_hash` | String (Unique)| Hash forense da linha. (Atrela data, status e evento anterior). |
| `status` | String | Tipo de Evento Sourcing (ex: 'given', 'revoked', 'forgotten'). |
| `parent_hash` | String | Hash concatenado da linha pregressa formando a *"Corrente de Blocos"*. |
| `sequence_version`| Integer | Captura da versão de concorrência garantindo prova cronológica e unicidade do disparo. |

---

## 7. Referência da API (Endpoints Core)

A lógica negocial ocorre nestas frentes restritas via HTTP REST.

### `POST /consents`
Cria um novo ciclo de rastreabilidade para o engajamento com uma Política.
- **Autenticação:** Header `Bearer <JWT_TOKEN>`.
- **Validação de Payload:** Obriga que o `body` forneça `id_policy`, `channel` e `status`.
- **Ação Restrita:** Identidade puramente forçada pelo Token JWT. 

### `GET /consents/user/<user_id>`
Auto-consulta do histórico completo do indivíduo.
- **Autenticação:** Header `Bearer <JWT_TOKEN>`.
- **Auditoria Zero-Trust:** Bloqueia sumariamente caso as "Claims" do payload JWT não correspondam intrinsicamente ao `user_id` procurado pelo endpoint HTTP (Anti-sniffing de terceiros).

### `DELETE /users/<user_id>/forget`
Engatilha a Lápide e o apagamento sistêmico LGPD (Crypto-shredding lógico).
- **Autenticação:** Header `Bearer <JWT_TOKEN>`.
- **Ação:** Aplica a flag `pending_deletion=True` ativando remotamente a roleta do *Worker*.

### `GET /consents/policy/<policy_id>`
Auditoria Aberta (Ledger Viewer).
- **Ação:** Lista cronologicamente os hashes perante o documento selecionado. Dispensa Tokens pois trabalha 100% sobre dados não pessoais (`subject_pseudonym`).

### `GET /admin/consents/user/<user_id>`
Backoffice Pericial M2M.
- **Autenticação:** Header `Bearer <ADMIN_TOKEN>`.
- **Ação:** Concede ao DPO a habilidade de cruzar o Id e reconstruir temporariamente o mapa total de ações criptográficas de um CPF específico.

---

## 8. Fluxograma para a Demonstração (PoC)

O ambiente inteiro foi pensado de modo que o encadeamento de eventos e as respostas de interface funcionem como cenários da vida real. O passo-a-passo da demonstração segue a seguinte cadência:

### Acesso e Criação
1. **Identidade (Mock IdP):** O titular interage simbolicamente através de uma interface cliente. O endpoint (microsserviço mock) fornece um Token JWT autêntico, garantindo sua própria legitimidade que será enviada aos microserviços centrais.
2. **Registro Natural (API-Consentimentos):** Ao simular a assinatura da Política, a requisição passa pelos validadores (extrai-se a identidade oculta no Token).
3. **Auditoria Linear:** A API busca/cria a âncora via `UserCrypto`, gera o Salt para Pseudonimização forte, injeta os dados de rastreio (`parent_hash`), calcula o hash completo e gera a primeira linha do livro contábil (`Consents`).

### Alteração e Acréscimo
1. **Nova Modificação de Política:** Um usuário interage com uma nova atualização e consente (ou revoga) os acessos.
2. **Evidência Temporal (Sequence e Hash Chain):** Como um usuário contínuo já rastreado, a API captura e sincroniza o `sequence_version` a partir do `UserCrypto.version` atual localizando o respectivo `parent_hash`, fechando a prova criptográfica do evento n° 2 blindando contra Race Conditions no banco através do mecanismo ORM.
3. Se houvesse intervenção mecânica indesejada e não-legítima de atualização da base de logs recém criada, os gatilhos intrínsecos de Append-Only disporiam-se a anular e estourar uma Exceção Crítica de Integridade.

### Clean-Up Lógico
1. **Ação de Retrato:** O usuário reivindica o apagamento perene de seus rastros.
2. **Deleção Programada:** Ele aciona a rota local da API, que age via *Soft-delete* marcando a urgência sem alterar a linha do tempo principal.
3. **Tombstone Final pelo Administrador Imparcial (Worker)**: Em background, varreduras programadas buscam as Flags (Semáforos).
    - Elas anexam no log formal que aquela assinatura de Identidade emudeceu (`USER_FORGOTTEN`).
    - Destroem para todo o sempre o `UserCrypto` (o Salt contido), realizando o desvínculo vitalício com os logs (Cripto-Shredding e Direito ao Esquecimento).
4. O administrador de compliance, via **Admin-Panel** só visualiza o identificador randomizado atrelado aos *timestamps*, impossibilitado de enxergar qualquer PII ou rastreabilidade cruzada.
