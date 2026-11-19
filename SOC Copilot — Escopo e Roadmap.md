# SOC Copilot — Escopo e Roadmap

Nov 13, 2026 · atualizado em 19 nov 2026 · @Jon

## Visão geral

O SOC Copilot é um agente de IA que lê logs de segurança, agrupa os eventos em incidentes, classifica a gravidade, explica o que aconteceu e sugere a resposta, tudo medido contra um baseline de regras. A meta é ter um MVP no ar em 8 semanas, com um link público e uma tabela de resultados no README.

- **Problema:** analistas de SOC iniciantes e equipes pequenas se afogam em alertas. A maioria é ruído, e os poucos incidentes reais se perdem no meio.
- **Usuário-alvo:** um analista de SOC nível 1 ou um sysadmin de uma empresa pequena, sem ferramenta de SIEM paga.
- **Por que serve ao portfólio:** um mesmo projeto prova três perfis de vaga. Para AI Engineer, mostra agente, RAG e evals. Para cibersegurança, mostra detecção e o mapeamento no MITRE ATT&CK. Para SRE, mostra deploy, observabilidade e controle de custo.
- **Idioma:** código, README e demo em inglês, para concorrer a vagas remotas fora do Brasil.

## Escopo do MVP

O MVP faz bem uma coisa: transforma um lote de logs em uma lista curta de incidentes explicados. Todo o resto vem depois.

**Entra no MVP**

- Ingestão via REST de logs sintéticos em JSON de cinco tipos de fonte: `auth.log` do Linux (SSH), firewall, gateway de e-mail e proxy, eventos de segurança do Windows e DNS. Eles cobrem os 5 cenários do gerador: brute force SSH, port scan, phishing, lateral movement e exfiltração por DNS.
- Normalização para um esquema único de evento: fonte (`source`), tipo (`event_type`), timestamp e o dado bruto em JSON (`raw_data`), que carrega host, usuário e IP de origem.
- Agrupamento dos eventos em incidentes por IP, usuário e janela de tempo. Implementado em `services/correlation.py` e exposto em `POST /api/v1/analyze/auto`; o `/analyze` continua recebendo um grupo já escolhido.
- Classificação feita pelo LLM: estágio do ataque (do qual o código deriva a gravidade de 1 a 4: baixa, média, alta ou crítica), técnica do MITRE ATT&CK, explicação em até 5 linhas e ações sugeridas.
- RAG sobre um subconjunto de 15 técnicas do MITRE ATT&CK, para citar a técnica com o link oficial.
- Painel web com a lista de incidentes, o detalhe de cada um e os eventos de origem.
- Suíte de evals rodando no CI a cada pull request.

**Fica de fora**

- Coleta em tempo real com agentes instalados nas máquinas (o MVP recebe os logs pelo endpoint REST).
- Parsers de logs reais (Nginx, exportação de eventos do Windows por ID, firewall) e cenários web como SQL injection e path traversal. Ficam para a v2.
- Resposta automática, como bloquear um IP. O agente só sugere a ação.
- Contas de vários usuários e cobrança.
- Fine-tuning de modelo.

## Arquitetura e stack

### Componentes

| Componente | Tecnologia | Papel |
| --- | --- | --- |
| Frontend | React 18 + TypeScript + Vite | Dashboard de incidentes, timeline, filtros |
| API | FastAPI (Python 3.12+) | Ingestão de logs, orquestração do agente, REST |
| LLM | Modelo local via Ollama (padrão, `qwen2.5:3b`), Claude ou OpenAI (plugável) | Classificação e sugestão de resposta |
| Banco relacional | PostgreSQL 16 | Eventos brutos, incidentes, audit log |
| Banco vetorial | pgvector (extensão do Postgres) | Embeddings do MITRE ATT&CK para RAG |
| Fila e cache | Redis 7 | Já no compose, ainda sem uso; reservado para fila de ingestão e cache |
| Infra | Docker Compose + Caddy | Orquestração local e de produção (Caddy faz o TLS); CI via GitHub Actions |
| Evals | pytest + DeepEval | Testes de acurácia, latência e regressão do agente |

### Fluxo de dados

1. **Ingestão** — logs simulados (formato CEF ou JSON) entram via endpoint REST (a fila Redis fica para depois).
2. **Pré-processamento** — normalização de campos, deduplicação, enriquecimento com regras Sigma-style (baseline determinístico).
3. **Agente LLM** — recebe eventos agrupados + contexto RAG (táticas MITRE) e retorna: veredito (incidente ou não), estágio do ataque, tática e técnica MITRE, resumo do incidente e ações sugeridas. A gravidade sai do estágio, em código.
4. **Checagem de evidências** — o código confere o veredito e o estágio contra o que os eventos mostram (`services/evidence.py`): limita o estágio ao que as evidências sustentam e derruba o "incidente" quando não há nenhum passo de ataque. Só age sobre tipos de evento que sabe ler.
5. **Persistência** — incidente salvo no PostgreSQL com link aos eventos originais.
6. **Dashboard** — React exibe incidentes em tempo quase-real, com filtros por severidade, tática e período.

### Decisões de design

- **LLM plugável** — interface abstrata permite trocar entre Claude e OpenAI sem alterar o resto do código. Útil para comparar custo e qualidade nos evals.
- **RAG sobre MITRE ATT&CK** — em vez de colocar toda a base MITRE no prompt, usamos pgvector para buscar apenas as técnicas relevantes, reduzindo tokens e melhorando precisão.
- **Baseline determinístico** — regras Sigma-style rodam antes do LLM. Servem como piso de comparação nos evals e como fallback se o LLM estiver indisponível.
- **Modelo local como padrão** — o projeto roda sem conta e sem chave, com Ollama no próprio compose. Claude e OpenAI ficam a uma variável de distância.
- **O modelo nomeia o estágio, o código dá a nota** — o LLM diz até onde o ataque chegou (nenhum, reconhecimento, tentativa, sucesso) e a política de gravidade (`services/severity.py`) converte em 1 a 4. Com o qwen2.5:7b, o acerto de gravidade subiu de 28% para 65%.
- **Evidências seguram o agente** — o modelo exagerava ("sucesso" em port scan, incidente em atividade comum). Checagens em código, frouxas de propósito, limitam o estágio e vetam o falso alarme, mas só em grupos cujos eventos elas sabem ler; o resto fica com o modelo, para ele continuar pegando o que as regras não descrevem.

## Avaliação (evals)

O diferencial do projeto é provar, com números, que o agente supera um baseline simples de regras. Os resultados ficam numa tabela no README, atualizada pelo CI.

**Dataset**

- No MVP, 67 entradas rotuladas (golden dataset: 24 ataques padrão, 19 evasivos e 24 benignas), cada uma com a lista de eventos, a gravidade esperada (1 a 4), a tática e a técnica ATT&CK.
- A base são os 5 cenários sintéticos de `generate_logs.py`, com variações: thresholds diferentes, combinações de cenários e falsos positivos deliberados (atividade benigna parecida com ataque).
- 15 das 67 entradas (22%) ficam separadas como conjunto de teste e nunca são usadas para ajustar o prompt.
- Depois do MVP: ampliar para cerca de 200 cenários com ataques de laboratório próprio (Kali contra VMs no VirtualBox: password spraying, criação de conta suspeita, SQL injection e path traversal no Nginx), misturados com tráfego normal em torno de 70% de eventos benignos.

**Métricas**

Esta tabela é a fonte única das metas; o roadmap aponta para ela.

| Métrica | O que mede | Meta | Quando | Última rodada real |
| --- | --- | --- | --- | --- |
| Acerto de gravidade | Gravidade igual à do rótulo | ≥ 75% | Fase 3 | 98% ✅ |
| Acerto de tática ATT&CK | Tática igual à do rótulo | ≥ 70% | Fase 3 | 72% ✅ |
| Acerto de técnica ATT&CK | ID da técnica igual ao do rótulo | ≥ 65% | Fase 3 | 72% ✅ |
| Latência p95 | Tempo de uma chamada ao `/analyze` (um incidente) | < 10 s | Fase 3 | 341 s ❌ (CPU) |
| Custo | Dólares por incidente analisado | Registrar e reduzir | Fase 3 | $0 (modelo local) |
| Recall de detecção | Ataques reais que o sistema encontrou | ≥ 90% | Fase 3 (medido, sem gate no CI) | 98% ✅ |
| Precisão de detecção | Alertas que eram ataques de verdade | ≥ 80% | Fase 3 (medido, sem gate no CI) | 86% ✅ (7 falsos positivos) |
| Qualidade da explicação | Nota de 1 a 5 dada por LLM-as-judge com rubrica | ≥ 4,0 | Depois da primeira rodada | Não medido |
| Latência em lote | Tempo para analisar 1.000 eventos | ≤ 30 s | Ainda não medido | Não medido |

A "última rodada real" é o qwen2.5:7b em CPU de 19 nov 2026, medindo o commit `c232644` (o limite de estágio e o veto aos grupos sem passo de ataque). O veto levou os falsos positivos de 18 para 7 e a precisão de 70% para 86%, exatamente o que o replay previa; o resto não mudou. Sem o limite de estágio, a gravidade era 65%. As checagens foram escritas olhando o dataset, então o número honesto é o do conjunto de teste separado: gravidade de 9 em 10, precisão de 90% e 1 falso positivo nas 5 entradas benignas.

O `AnalysisResult` tem o campo `is_incident`, então o agente pode responder "não é incidente" e o falso positivo é medido nas 24 entradas benignas do dataset. As metas são um ponto de partida e devem ser revistas depois da primeira rodada.

**Baseline**

- Regras fixas no estilo Sigma: por exemplo, mais de 10 falhas de login do mesmo IP em 5 minutos gera um alerta.
- O README mostra as duas colunas lado a lado, baseline e agente, mais os casos em que o agente errou e por quê.

**Ferramentas:** pytest com DeepEval, rodando no GitHub Actions.

## Como rodar o que já está pronto

O projeto inteiro está nesta pasta (reconstruído aqui a partir deste documento; a cópia em `Documents\soc-copilot` do notebook não foi usada). Com Docker, `docker compose up -d --build` sobe tudo, com o painel em `http://localhost:3000`. Para rodar o backend fora do Docker:

1. Instalar Docker Desktop e ter Python 3.12+
2. `docker compose up -d db redis` — sobe Postgres 16 + pgvector e Redis
3. `cd backend && pip install -r requirements-dev.txt`
4. Opcional: sem `.env`, o padrão é o Ollama local (`docker compose up -d ollama`). Para um modelo hospedado, copiar `.env.example` para `.env` e preencher `LLM_PROVIDER=claude` (ou `openai`) e a API key
5. `python scripts/seed_mitre.py` — popula as 15 técnicas MITRE com embeddings
6. `python scripts/generate_logs.py` — gera logs sintéticos dos 5 cenários
7. `uvicorn app.main:app --reload` — sobe a API na porta 8000
8. Testar: `curl -X POST http://localhost:8000/api/v1/analyze -H 'Content-Type: application/json' -d '{"event_ids": [1,2,3]}'`
9. Rodar testes: `pytest -v` (86 testes unitários devem passar)
10. Rodar evals: `pytest backend/tests/evals -m eval -v` na raiz (gera `evals/results.json`; a parte do agente precisa do Ollama no ar ou de uma API key; com o qwen2.5:7b em CPU são 68 chamadas e de 2 a 4 horas)

As Fases 1 a 4 estão implementadas. O que falta, em ordem:

1. Medir o inventário de ativos numa rodada real. Feito em código (`services/assets.py`, `ASSET_INVENTORY`): no replay, os 7 falsos positivos restantes (3 credenciais vencidas de CI, 4 jobs de backup) somem e nenhum ataque muda; um teste garante que o inventário não põe de lado nenhum evento de ataque do dataset.
2. Rodar uma vez com Claude para ter latência e custo reais; nenhum modelo local em CPU chega aos 10 s.
3. Escolher o host, fazer o deploy e gravar o GIF.
4. Adicionar o badge do CI e o LLM-as-judge.

### Arquivos já construídos (referência)

| Arquivo | O que faz |
| --- | --- |
| `docker-compose.yml` | Sobe Postgres 16 + pgvector, Redis, Ollama, API e frontend |
| `docker-compose.prod.yml` + `Caddyfile` | Stack de produção: Caddy com TLS como única porta pública, modo demo ligado |
| `backend/Dockerfile` | Build da imagem Python da API |
| `backend/requirements.txt` | Dependências (FastAPI, SQLAlchemy, sentence-transformers, etc.) |
| `pyproject.toml` | Config do ruff (linter) |
| `.github/workflows/ci.yml` | CI: lint, testes unitários, build do frontend, validação dos compose e evals |
| `backend/app/main.py` | Entrypoint FastAPI com routers |
| `backend/app/core/config.py` | Settings via pydantic-settings (.env) |
| `backend/app/core/database.py` | Engine e SessionLocal do SQLAlchemy async |
| `backend/app/models/event.py` | Modelo Event (logs brutos) |
| `backend/app/models/incident.py` | Modelo Incident (incidentes classificados) |
| `backend/app/models/mitre.py` | Modelo MitreTechnique (com coluna vector) |
| `backend/app/schemas/event.py` | Pydantic schemas de Event |
| `backend/app/schemas/incident.py` | Pydantic schemas de Incident |
| `backend/app/schemas/analysis.py` | Request/Response do /analyze |
| `backend/app/api/v1/events.py` | CRUD de eventos |
| `backend/app/api/v1/incidents.py` | CRUD de incidentes |
| `backend/app/api/v1/analyze.py` | Endpoint principal: RAG + Sigma + LLM |
| `backend/app/services/rag.py` | RAG: busca técnicas MITRE por similaridade |
| `backend/app/services/llm.py` | Providers LLM (Ollama, Claude, OpenAI) + factory |
| `backend/app/services/severity.py` | Política de gravidade e mapa estágio → gravidade |
| `backend/app/services/evidence.py` | Checagem de evidências: limita o estágio e veta falsos alarmes |
| `backend/app/services/assets.py` + `app/data/synthetic_assets.json` | Inventário de ativos conhecidos: põe de lado a rotina do servidor de backup e do runner de CI |
| `backend/app/services/cef.py` | Parser de linhas CEF |
| `backend/app/core/demo.py` | Modo demo: API só leitura e limite de análises por IP e por dia |
| `backend/app/services/sigma_rules.py` | 5 regras determinísticas de detecção |
| `backend/scripts/generate_logs.py` | Gerador de 5 cenários de logs sintéticos |
| `backend/scripts/seed_mitre.py` | Seed de 15 técnicas ATT&CK com embeddings |
| `backend/tests/test_*.py` | 86 testes unitários (parsing do LLM, demo, evidências, schemas, sigma, logs, health) |
| `backend/app/services/correlation.py` | Agrupa eventos por IP, usuário e janela de tempo |
| `backend/app/services/analysis.py` | Orquestração: RAG + Sigma + LLM + persistência |
| `backend/scripts/build_golden.py` | Gera `tests/evals/golden_labels.json` a partir dos geradores |
| `backend/tests/evals/` | Harness, evals do agente e comparativo com o baseline |
| `backend/scripts/update_readme.py` | Gera a tabela do README a partir de `evals/results.json` |
| `backend/scripts/seed_demo.py` | Popula a demo pública com os 5 cenários já analisados |
| `README.pt-BR.md` | README em português, com troca de idioma |
| `frontend/` | Painel React (Incidents, Analyze, Metrics) + Nginx |

### Contexto técnico para IA continuar o projeto

Quem for gerar código para as Fases 3 e 4 precisa seguir estes padrões já estabelecidos:

**Stack e versões**

- Python 3.12, FastAPI 0.115+, SQLAlchemy 2.x async (asyncpg), Pydantic v2
- Postgres 16 com extensão pgvector (tipo `Vector(384)` para embeddings all-MiniLM-L6-v2)
- Redis 7 (no compose, ainda sem uso; para cache futuro)
- Linter: ruff (config em `pyproject.toml`); CI roda `ruff check` e `pytest`
- Testes: pytest + pytest-asyncio

**Padrões de código**

- Endpoints em `backend/app/api/v1/<recurso>.py`, cada um com `router = APIRouter(tags=[...])`
- Models SQLAlchemy em `backend/app/models/`, importados via `__init__.py`
- Schemas Pydantic em `backend/app/schemas/`
- Services (lógica de negócio) em `backend/app/services/`
- Config via `pydantic_settings.BaseSettings` em `core/config.py`, lê `.env`
- Database: `async_sessionmaker` em `core/database.py`, dependency injection via `get_session()`
- Routers incluídos em `main.py` com `app.include_router(router, prefix="/api/v1")`

**Modelo de dados existente**

- `Event`: id, source (str), event\_type (str), raw\_data (JSON), timestamp, severity (int nullable), incident\_id (FK nullable)
- `Incident`: id, title, severity (1–4), status (open/investigating/resolved), summary, mitre\_tactic, mitre\_technique, mitre\_technique\_name, suggested\_actions, confidence, classified\_by (llm ou sigma), sigma\_result, created\_at, updated\_at
- `MitreTechnique`: id, technique\_id (ex: T1110), name, tactic, description, detection\_hints, embedding (Vector 384)

**Endpoint /api/v1/analyze (orquestração)**

- Recebe `AnalyzeRequest`: event\_ids (list\[int\]) ou events (list inline), use\_sigma (bool, default true), top\_k (int, default 5), persist (bool, default true)
- Fluxo: coleta eventos → RAG busca técnicas MITRE (cosine distance via pgvector `<=>`) → roda regras Sigma → chama LLM → `settle_stage` confere a resposta contra as evidências → persiste Incident → retorna `AnalyzeResponse` com `sigma_result` e `llm_result`

**LLM Service (pluggable)**

- ABC `LLMProvider` com método `async analyze(events_text, mitre_context) -> AnalysisResult`
- `OllamaProvider` (padrão; API nativa do Ollama com saída restrita ao JSON schema, `OLLAMA_MODEL`), `ClaudeProvider` (`claude-sonnet-5-5` por padrão, configurável em `ANTHROPIC_MODEL`; saída estruturada e fallback de recusa no servidor) e `OpenAIProvider` (gpt-4o-mini, ChatCompletion)
- Factory `get_llm_provider()` retorna singleton baseado em `settings.llm_provider`
- `_parse_response(raw)` faz strip de markdown fences, parse JSON, deriva a gravidade do `attack_stage` e cai para severity=3 se o parse falhar
- `AnalysisResult`: is\_incident (bool), severity (clamped 1–4), attack\_stage (none, reconnaissance, attempt, success), evidence\_note (preenchido quando a checagem mudou algo), summary, mitre\_tactic, mitre\_technique\_id, mitre\_technique\_name, suggested\_actions (list\[str\]), confidence (float)

**Checagem de evidências**

- `settle_stage(result, events)` em `services/evidence.py`, chamado em `analyze_events` só sobre a resposta do LLM
- Achados: login depois de 5+ falhas do mesmo IP, download, uma origem alcançando outros hosts, formato de túnel DNS (exceto CDNs), e-mail com domínio novo ou SPF falho sem relay de lista, varredura de 10+ alvos
- O estágio fica limitado ao maior achado; Discovery para em reconhecimento; Lateral Movement e Exfiltration com evidência sobem para sucesso; sem nenhum achado, o incidente é vetado
- Limite e veto só valem quando todos os eventos são de tipos conhecidos (`KNOWN_KINDS`); com qualquer outro tipo, a resposta do modelo passa
- Antes das checagens, saem os eventos que são rotina de um ativo do inventário (`ASSET_INVENTORY`, vazio por padrão): IP de origem, nome do host, conta e tipo de evento precisam bater. O nome do ativo vai para o `evidence_note`

**Regras Sigma (baseline)**

- 5 regras em `sigma_rules.py`: brute\_force\_ssh, port\_scan, phishing, lateral\_movement, dns\_exfiltration
- Cada regra inspeciona events por source/event\_type, verifica thresholds, retorna dict com severity, summary, mitre\_tactic, mitre\_technique, suggested\_actions
- `run_sigma_rules(events)` retorna primeiro match ou None

**RAG Service**

- `retrieve_mitre_techniques(session, query_text, top_k)` → embed query com SentenceTransformer (lazy singleton), busca top\_k por cosine distance, retorna list\[dict\] com technique\_id, name, tactic, description, detection\_hints, distance

**Cenários de teste existentes (usar como base para golden labels)**

- Brute force SSH: 15+ eventos auth.log com "Failed password", source="auth.log", event\_type="authentication\_failure"
- Port scan: 25+ conexões rápidas de mesmo IP, source="firewall", event\_type="connection\_attempt"
- Phishing: email suspeito + clique em link + download, source="email\_gateway"/"proxy", event\_type varia
- Lateral movement: login de IP interno incomum + acesso a shares, source="windows\_security", event\_type="logon"/"share\_access"
- DNS exfiltration: queries DNS longas e frequentes para mesmo domínio, source="dns", event\_type="query"

**Variáveis de ambiente (.env)**

- `DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:5432/soc_copilot`
- `REDIS_URL=redis://localhost:6379/0`
- `LLM_PROVIDER=ollama` (padrão: modelo local, sem API key), ou `claude`, ou `openai`
- `OLLAMA_MODEL=qwen2.5:3b` e `OLLAMA_BASE_URL=http://localhost:11434` (só com `ollama`; no Docker Compose o Ollama já sobe junto e baixa o modelo)
- `ANTHROPIC_API_KEY=sk-ant-...`
- `OPENAI_API_KEY=sk-...`

**Frontend (feito na Fase 4)**

- `frontend/` com Vite + React + TypeScript + Tailwind e React Query, páginas Incidents, IncidentDetail, Analyze e Metrics
- Consome `GET /api/v1/incidents`, `POST /api/v1/analyze` e `GET /api/v1/metrics`
- Serviço `frontend` no `docker-compose.yml`: Nginx servindo o build estático, com proxy reverso para `/api`

## Roadmap por fases

### Fase 1 — Fundação ✅ CONCLUÍDA

- Criar repositório com estrutura de pastas, Docker Compose (Postgres + Redis + API), CI básico (lint + testes unitários).
- Modelar schema do banco: tabelas de eventos brutos e incidentes.
- Endpoint de ingestão REST que recebe logs CEF/JSON e persiste no Postgres.
- Script gerador de logs sintéticos (5 cenários: brute force SSH, port scan, phishing, lateral movement, exfiltração).
- **Entrega:** `docker compose up` sobe a stack, logs entram e aparecem no banco.

### Fase 2 — Agente LLM + RAG ✅ CONCLUÍDA

- Popular pgvector com embeddings de 15 técnicas MITRE ATT&CK (Enterprise).
- Implementar pipeline RAG: dado um grupo de eventos, buscar técnicas MITRE relevantes e montar o prompt.
- Criar o agente (chamada à API do LLM) que retorna: severidade, tática/técnica MITRE, resumo e ações sugeridas.
- Implementar regras Sigma-style como baseline determinístico.
- **Entrega:** endpoint `/api/v1/analyze` recebe eventos e retorna classificação estruturada.

### Fase 3 — Evals e CI ✅ IMPLEMENTADA (metas em parte atingidas)

**Estado em 18 nov 2026:** o agente já rodou nos evals com qwen2.5:3b e qwen2.5:7b em CPU, e os números estão no README. Na última rodada real (19 nov), com o limite de estágio e o veto, gravidade (98%), tática (72%), técnica (72%), recall (98%) e precisão (86%) batem a meta; só a latência (341 s) não. A latência só cai com GPU ou modelo hospedado.


- **3.1 — Golden dataset** `backend/tests/evals/golden_labels.json`: criar arquivo JSON com 50–100 incidentes rotulados. Cada entrada tem: lista de eventos (raw logs), severidade esperada (1–4), tática MITRE esperada, técnica MITRE esperada. Usar os 5 cenários de `generate_logs.py` como base e adicionar variações (thresholds diferentes, combinações, falsos positivos deliberados). Separar 20% das entradas como conjunto de teste.
- **3.2 — Suite de evals com DeepEval** `backend/tests/evals/test_eval_agent.py`: instalar `deepeval` via pip. Para cada entrada do golden dataset: chamar `/api/v1/analyze`, comparar resposta do agente com o label esperado. Métricas e metas: as marcadas como Fase 3 na tabela da seção Avaliação (acerto de gravidade ≥ 75%, de tática ≥ 70%, de técnica ≥ 65%, latência p95 < 10 s por chamada, custo registrado).
- **3.3 — Comparativo agente vs. baseline** `backend/tests/evals/test_eval_comparison.py`: rodar o mesmo golden dataset pelas regras Sigma (`sigma_rules.py`). Gerar tabela comparativa em JSON: agente LLM vs. baseline determinístico em cada métrica. Salvar em `evals/results.json`.
- **3.4 — CI** `.github/workflows/ci.yml`: adicionar job `eval` ao workflow. Precisa de `ANTHROPIC_API_KEY` ou `OPENAI_API_KEY` como secret do repo. Rodar `pytest backend/tests/evals -m eval -v` com timeout de 5 min. Publicar `evals/results.json` como artefato do CI.
- **3.5 — Badge e README** (tabela feita; falta o badge): adicionar badge do GitHub Actions no topo do `README.md`. Criar seção "Eval Results" com tabela comparativa lida do `results.json`.
- **Entrega:** CI rodando evals a cada PR; tabela comparativa agente vs. baseline visível no README; accuracy de severidade ≥ 75%.

### Fase 4 — Dashboard e polish ✅ IMPLEMENTADA (faltam o GIF e o deploy, itens 4.7 e 4.8; a stack de produção está pronta)

- **4.1 — Scaffold React** `frontend/`: criar app React com Vite + TypeScript. Instalar Tailwind CSS, React Query, React Router. Configurar proxy para `http://localhost:8000` no `vite.config.ts`. Criar layout base com sidebar (Incidentes, Métricas) e topbar.
- **4.2 — Página de incidentes** `frontend/src/pages/Incidents.tsx`: tabela com colunas: ID, severidade (badge colorido 1–4), tática MITRE, data, status. Paginação. Filtros por severidade e tática. Chamar `GET /api/v1/incidents`.
- **4.3 — Detalhe do incidente** `frontend/src/pages/IncidentDetail.tsx`: timeline vertical de eventos do incidente. Card com análise do agente: severidade, resumo, técnica MITRE (link para attack.mitre.org), ações sugeridas. Card com resultado Sigma como comparação.
- **4.4 — Página de métricas** `frontend/src/pages/Metrics.tsx`: ler `evals/results.json` via endpoint dedicado. Exibir: acerto de gravidade, de tática e de técnica, latência p95. Gráfico de barras agente vs. baseline.
- **4.5 — Análise ao vivo** `frontend/src/pages/Analyze.tsx`: formulário para colar/digitar logs JSON. Botão "Analisar" chama `POST /api/v1/analyze`. Exibe resultado em tempo real com loading spinner.
- **4.6 — Docker Compose** `docker-compose.yml`: adicionar serviço `frontend` (Nginx servindo build estático). Proxy reverso no Nginx para `/api` apontar ao backend. Portas: frontend 3000, backend 8000.
- **4.7 — README completo** `README.md`: GIF de demo (gravar com asciinema ou screen recording), diagrama de arquitetura (Mermaid), instruções "como rodar" com 3 comandos, seção de resultados dos evals, link para demo ao vivo.
- **4.8 — Deploy** (pronto para subir: `docker-compose.prod.yml` com Caddy, modo demo só leitura e limite de análises; falta escolher o host) Fly.io, Render, Railway ou VPS: fazer deploy da stack Docker Compose completa. Configurar variáveis de ambiente (API keys, DATABASE\_URL). Verificar URL pública acessível.
- **Entrega:** projeto completo com frontend funcional, URL ao vivo, README com GIF e métricas, repositório público pronto para portfólio.

### Marcos de validação

| Marco | Critério de aceite |
| --- | --- |
| M1 — Stack rodando ✅ | `docker compose up` sem erros, logs no banco |
| M2 — Agente funcional ✅ | `/analyze` retorna JSON válido com campos MITRE |
| M3 — Evals passando ✅ | Accuracy de severidade acima de 75%; CI verde (gravidade de 98% na rodada de 18 nov; CI verde) |
| M4 — Demo ao vivo | URL pública acessível, GIF no README |

## Estrutura do repositório e README

O repositório precisa ser fácil de entender para quem nunca falou com você, porque é isso que uma vaga remota avalia.

```
soc-copilot/
├── backend/
│   ├── app/
│   │   ├── api/v1/           # endpoints (events, incidents, analyze)
│   │   ├── core/             # config, database
│   │   ├── models/           # SQLAlchemy (Event, Incident, MitreTechnique)
│   │   ├── schemas/          # Pydantic (event, incident, analysis)
│   │   ├── services/         # rag, llm, sigma_rules, severity, evidence, assets, correlation, analysis
│   │   └── main.py
│   ├── scripts/
│   │   ├── generate_logs.py  # 5 cenários sintéticos
│   │   └── seed_mitre.py     # 15 técnicas ATT&CK com embeddings
│   ├── tests/
│   │   ├── test_*.py         # unitários (86 testes passando)
│   │   └── evals/            # golden labels + DeepEval
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                 # React + Vite + Tailwind + Nginx
├── evals/
│   └── results.json          # gerado pelos evals
├── .github/workflows/ci.yml  # lint + testes + build do frontend + evals
├── docker-compose.yml        # Postgres 16 + pgvector, Redis, Ollama, API, frontend
├── docker-compose.prod.yml   # produção: Caddy com TLS, modo demo
├── pyproject.toml            # ruff config
└── README.md
```

**O README, nesta ordem**

1. Uma frase dizendo o que o projeto faz, com o link da demo e um GIF de 20 segundos.
2. A tabela de resultados: baseline contra agente.
3. O diagrama de arquitetura.
4. Como rodar localmente em até 3 comandos, a partir de `docker compose up`.
5. Decisões e trade-offs: por que esse modelo, por que pgvector, quanto custa.
6. Limitações conhecidas e próximos passos.

**Hábitos que contam ponto:** commits pequenos e descritivos, issues e pull requests mesmo trabalhando sozinho, e um ADR curto para cada decisão grande.

## Como divulgar

Um projeto que ninguém vê não gera entrevista, então a divulgação é parte do roadmap, não um extra.

- **LinkedIn:** três posts em inglês, um por marco: o agente funcionando, a primeira rodada de evals (com a tabela) e o lançamento com a demo.
- **Artigo técnico:** um texto no dev.to ou Medium sobre como medir um agente de segurança contra um baseline. É o que gera link e conversa com recrutadores.
- **Portfólio:** o projeto em destaque no fernando-johansen.vercel.app, com GIF, tabela de resultados e links para demo e repositório.
- **Currículo:** uma linha com números, por exemplo: “Built an LLM-based security log triage agent; 92% recall vs 61% for a rule baseline, at $0.04 per 1,000 events.” (os números são ilustrativos; use os reais).
- **Entrevista:** prepare uma explicação de 2 minutos da arquitetura e dos trade-offs, porque é a pergunta que sempre vem.
- **Sigilo:** o projeto mostra a competência sem precisar citar nenhum detalhe do trabalho na Marinha.

## Riscos e decisões em aberto

O maior risco é o custo e a qualidade do LLM com volumes grandes de log. Por isso, a correlação deve ser feita em código antes, para que o modelo só veja incidentes já agrupados.

| Risco | Mitigação |
| --- | --- |
| Custo de API alto com muitos eventos | Agrupar antes de chamar o LLM, cache por assinatura de incidente e limite de gasto mensal |
| Alucinação na técnica ATT&CK | RAG sobre a base oficial e saída validada contra a lista de IDs |
| Dataset pequeno ou enviesado | Variações sintéticas e conjunto de teste separado no MVP; depois, cenários de laboratório e logs públicos de segurança |
| Escopo crescer e o projeto não fechar | Congelar o escopo do MVP até a semana 8 |
| Logs com dado sensível na demo | Demo só com logs sintéticos e mascaramento de IPs e usuários |
| Checagem de evidências ajustada ao dataset sintético | Checagens frouxas e genéricas, número do conjunto de teste separado como o honesto, e o dataset de laboratório para validar fora do gerador |
| Conta do LLM na demo pública | Modo demo: API só leitura, 5 análises por IP por hora e 200 por dia, mais limite de gasto no console do provedor |

**Decisões em aberto**

- [x] Qual modelo usar? **Decidido:** arquitetura pluggable com factory pattern — suporta um modelo local via Ollama (o padrão, `qwen2.5:3b`, para rodar sem conta nem chave), Claude (`claude-sonnet-5-5`; o `claude-sonnet-4-20250514` original foi trocado pelo Sonnet atual) e OpenAI (gpt-4o-mini). Configurável via `LLM_PROVIDER` no `.env`.
- [ ] Onde hospedar a demo (Fly.io, Render, Railway ou uma VPS pequena)? A stack de produção já está pronta; qualquer servidor com 4 GB de RAM serve com um modelo hospedado.
- [x] Quando entra o agrupamento automático de eventos em incidentes? **Decidido:** já implementado (`POST /api/v1/analyze/auto`), agrupando por IP, usuário e janela de tempo.
- [x] Incluir parsers de logs reais de firewall no MVP? **Decidido:** não, ficam para v2. O cenário de port scan usa eventos sintéticos com `source="firewall"`. MVP usa 5 cenários: brute force SSH, port scan, phishing, lateral movement, DNS exfiltration.
- [x] Quanto tempo por semana? O roadmap original assumia 10h/semana. Fases 1 a 4 implementadas.
- [x] Como tratar os falsos positivos que os eventos não explicam (backup, CI)? **Decidido:** inventário de ativos consultado pelo código, não pelo prompt, porque dá para medir por replay e não depende de o modelo obedecer. Desligado por padrão: um inventário só serve para a rede que descreve.
