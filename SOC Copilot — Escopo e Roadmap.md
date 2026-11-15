# SOC Copilot — Escopo e Roadmap

Nov 13, 2026 · @Jon

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
- Classificação feita pelo LLM: gravidade de 1 a 4 (baixa, média, alta ou crítica), técnica do MITRE ATT&CK, explicação em até 5 linhas e ações sugeridas.
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
| LLM | Claude API ou OpenAI (plugável) | Classificação, correlação, sugestão de resposta |
| Banco relacional | PostgreSQL 16 | Eventos brutos, incidentes, audit log |
| Banco vetorial | pgvector (extensão do Postgres) | Embeddings do MITRE ATT&CK para RAG |
| Fila e cache | Redis 7 | Já no compose, ainda sem uso; reservado para fila de ingestão e cache |
| Infra | Docker Compose | Orquestração local; CI via GitHub Actions |
| Evals | pytest + DeepEval | Testes de acurácia, latência e regressão do agente |

### Fluxo de dados

1. **Ingestão** — logs simulados (formato CEF ou JSON) entram via endpoint REST (a fila Redis fica para depois).
2. **Pré-processamento** — normalização de campos, deduplicação, enriquecimento com regras Sigma-style (baseline determinístico).
3. **Agente LLM** — recebe eventos agrupados + contexto RAG (táticas MITRE) e retorna: severidade, tática e técnica MITRE, resumo do incidente e ações sugeridas.
4. **Persistência** — incidente salvo no PostgreSQL com link aos eventos originais.
5. **Dashboard** — React exibe incidentes em tempo quase-real, com filtros por severidade, tática e período.

### Decisões de design

- **LLM plugável** — interface abstrata permite trocar entre Claude e OpenAI sem alterar o resto do código. Útil para comparar custo e qualidade nos evals.
- **RAG sobre MITRE ATT&CK** — em vez de colocar toda a base MITRE no prompt, usamos pgvector para buscar apenas as técnicas relevantes, reduzindo tokens e melhorando precisão.
- **Baseline determinístico** — regras Sigma-style rodam antes do LLM. Servem como piso de comparação nos evals e como fallback se o LLM estiver indisponível.

## Avaliação (evals)

O diferencial do projeto é provar, com números, que o agente supera um baseline simples de regras. Os resultados ficam numa tabela no README, atualizada pelo CI.

**Dataset**

- No MVP, 67 entradas rotuladas (golden dataset: 24 ataques padrão, 19 evasivos e 24 benignas), cada uma com a lista de eventos, a gravidade esperada (1 a 4), a tática e a técnica ATT&CK.
- A base são os 5 cenários sintéticos de `generate_logs.py`, com variações: thresholds diferentes, combinações de cenários e falsos positivos deliberados (atividade benigna parecida com ataque).
- 15 das 67 entradas (22%) ficam separadas como conjunto de teste e nunca são usadas para ajustar o prompt.
- Depois do MVP: ampliar para cerca de 200 cenários com ataques de laboratório próprio (Kali contra VMs no VirtualBox: password spraying, criação de conta suspeita, SQL injection e path traversal no Nginx), misturados com tráfego normal em torno de 70% de eventos benignos.

**Métricas**

Esta tabela é a fonte única das metas; o roadmap aponta para ela.

| Métrica | O que mede | Meta | Quando |
| --- | --- | --- | --- |
| Acerto de gravidade | Gravidade igual à do rótulo | ≥ 75% | Fase 3 |
| Acerto de tática ATT&CK | Tática igual à do rótulo | ≥ 70% | Fase 3 |
| Acerto de técnica ATT&CK | ID da técnica igual ao do rótulo | ≥ 65% | Fase 3 |
| Latência p95 | Tempo de uma chamada ao `/analyze` (um incidente) | < 10 s | Fase 3 |
| Custo | Dólares por incidente analisado | Registrar e reduzir | Fase 3 |
| Recall de detecção | Ataques reais que o sistema encontrou | ≥ 90% | Fase 3 (medido, sem gate no CI) |
| Precisão de detecção | Alertas que eram ataques de verdade | ≥ 80% | Fase 3 (medido, sem gate no CI) |
| Qualidade da explicação | Nota de 1 a 5 dada por LLM-as-judge com rubrica | ≥ 4,0 | Depois da primeira rodada |
| Latência em lote | Tempo para analisar 1.000 eventos | ≤ 30 s | Ainda não medido |

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
4. Copiar `.env.example` para `.env` e preencher `ANTHROPIC_API_KEY` ou `OPENAI_API_KEY` + `LLM_PROVIDER=claude` (ou `openai`)
5. `python scripts/seed_mitre.py` — popula as 15 técnicas MITRE com embeddings
6. `python scripts/generate_logs.py` — gera logs sintéticos dos 5 cenários
7. `uvicorn app.main:app --reload` — sobe a API na porta 8000
8. Testar: `curl -X POST http://localhost:8000/api/v1/analyze -H 'Content-Type: application/json' -d '{"event_ids": [1,2,3]}'`
9. Rodar testes: `pytest -v` (37 testes devem passar)
10. Rodar evals: `pytest backend/tests/evals -m eval -v` na raiz (gera `evals/results.json`; a parte do agente precisa de API key)

As Fases 1 a 4 estão implementadas. O que falta depende de você: rodar os evals do agente com uma API key, gravar o GIF e fazer o deploy.

### Arquivos já construídos (referência)

| Arquivo | O que faz |
| --- | --- |
| `docker-compose.yml` | Sobe Postgres 16 + pgvector e Redis |
| `backend/Dockerfile` | Build da imagem Python da API |
| `backend/requirements.txt` | Dependências (FastAPI, SQLAlchemy, sentence-transformers, etc.) |
| `pyproject.toml` | Config do ruff (linter) |
| `.github/workflows/ci.yml` | CI básico: lint + testes unitários |
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
| `backend/app/services/llm.py` | Providers LLM (Claude/OpenAI) + factory |
| `backend/app/services/sigma_rules.py` | 5 regras determinísticas de detecção |
| `backend/scripts/generate_logs.py` | Gerador de 5 cenários de logs sintéticos |
| `backend/scripts/seed_mitre.py` | Seed de 15 técnicas ATT&CK com embeddings |
| `backend/tests/test_*.py` | 37 testes unitários (schemas, sigma, LLM parsing, health, logs) |
| `backend/app/services/correlation.py` | Agrupa eventos por IP, usuário e janela de tempo |
| `backend/app/services/analysis.py` | Orquestração: RAG + Sigma + LLM + persistência |
| `backend/scripts/build_golden.py` | Gera `tests/evals/golden_labels.json` a partir dos geradores |
| `backend/tests/evals/` | Harness, evals do agente e comparativo com o baseline |
| `backend/scripts/update_readme.py` | Gera a tabela do README a partir de `evals/results.json` |
| `frontend/` | Painel React (Incidents, Analyze, Metrics) + Nginx |

### Contexto técnico para IA continuar o projeto

Quem for gerar código para as Fases 3 e 4 precisa seguir estes padrões já estabelecidos:

**Stack e versões**

- Python 3.12, FastAPI 0.115+, SQLAlchemy 2.x async (asyncpg), Pydantic v2
- Postgres 16 com extensão pgvector (tipo `Vector(384)` para embeddings all-MiniLM-L6-v2)
- Redis 7 (para cache futuro, já no compose)
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
- `Incident`: id, title, severity (1–4), status (open/investigating/resolved), summary, mitre\_tactic, mitre\_technique, created\_at, updated\_at
- `MitreTechnique`: id, technique\_id (ex: T1110), name, tactic, description, detection\_hints, embedding (Vector 384)

**Endpoint /api/v1/analyze (orquestração)**

- Recebe `AnalyzeRequest`: event\_ids (list\[int\]) ou events (list inline), use\_sigma (bool, default true), top\_k (int, default 5), persist (bool, default true)
- Fluxo: coleta eventos → RAG busca técnicas MITRE (cosine distance via pgvector `<=>`) → roda regras Sigma → chama LLM → persiste Incident → retorna `AnalyzeResponse` com `sigma_result` e `llm_result`

**LLM Service (pluggable)**

- ABC `LLMProvider` com método `async analyze(events_text, mitre_context) -> AnalysisResult`
- `ClaudeProvider` (`claude-sonnet-5-5` por padrão, configurável em `ANTHROPIC_MODEL`; saída estruturada e fallback de recusa no servidor) e `OpenAIProvider` (gpt-4o-mini, ChatCompletion)
- Factory `get_llm_provider()` retorna singleton baseado em `settings.llm_provider`
- `_parse_response(raw)` faz strip de markdown fences, parse JSON, fallback com severity=3 se falhar
- `AnalysisResult`: is\_incident (bool), severity (clamped 1–4), summary, mitre\_tactic, mitre\_technique\_id, mitre\_technique\_name, suggested\_actions (list\[str\]), confidence (float)

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
- `LLM_PROVIDER=claude` (ou `openai`, ou `ollama` para um modelo local, sem API key)
- `OLLAMA_MODEL=llama3.1` e `OLLAMA_BASE_URL=http://localhost:11434/v1` (só com `ollama`)
- `ANTHROPIC_API_KEY=sk-ant-...`
- `OPENAI_API_KEY=sk-...`

**Para a Fase 4 (Frontend)**

- Criar `frontend/` com Vite + React + TypeScript + Tailwind
- Todos os endpoints REST já existem: `GET/POST /api/v1/events`, `GET/POST /api/v1/incidents`, `POST /api/v1/analyze`
- O frontend deve consumir esses endpoints via fetch/axios
- Adicionar serviço `frontend` ao `docker-compose.yml` (Nginx servindo build estático, proxy reverso para /api)

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

### Fase 3 — Evals e CI ✅ IMPLEMENTADA (falta rodar o agente com API key)

- **3.1 — Golden dataset** `backend/tests/evals/golden_labels.json`: criar arquivo JSON com 50–100 incidentes rotulados. Cada entrada tem: lista de eventos (raw logs), severidade esperada (1–4), tática MITRE esperada, técnica MITRE esperada. Usar os 5 cenários de `generate_logs.py` como base e adicionar variações (thresholds diferentes, combinações, falsos positivos deliberados). Separar 20% das entradas como conjunto de teste.
- **3.2 — Suite de evals com DeepEval** `backend/tests/evals/test_eval_agent.py`: instalar `deepeval` via pip. Para cada entrada do golden dataset: chamar `/api/v1/analyze`, comparar resposta do agente com o label esperado. Métricas e metas: as marcadas como Fase 3 na tabela da seção Avaliação (acerto de gravidade ≥ 75%, de tática ≥ 70%, de técnica ≥ 65%, latência p95 < 10 s por chamada, custo registrado).
- **3.3 — Comparativo agente vs. baseline** `backend/tests/evals/test_eval_comparison.py`: rodar o mesmo golden dataset pelas regras Sigma (`sigma_rules.py`). Gerar tabela comparativa em JSON: agente LLM vs. baseline determinístico em cada métrica. Salvar em `evals/results.json`.
- **3.4 — CI** `.github/workflows/ci.yml`: adicionar job `eval` ao workflow. Precisa de `ANTHROPIC_API_KEY` ou `OPENAI_API_KEY` como secret do repo. Rodar `pytest backend/tests/evals -m eval -v` com timeout de 5 min. Publicar `evals/results.json` como artefato do CI.
- **3.5 — Badge e README**: adicionar badge do GitHub Actions no topo do `README.md`. Criar seção "Eval Results" com tabela comparativa lida do `results.json`.
- **Entrega:** CI rodando evals a cada PR; tabela comparativa agente vs. baseline visível no README; accuracy de severidade ≥ 75%.

### Fase 4 — Dashboard e polish ✅ IMPLEMENTADA (faltam o GIF e o deploy, itens 4.7 e 4.8)

- **4.1 — Scaffold React** `frontend/`: criar app React com Vite + TypeScript. Instalar Tailwind CSS, React Query, React Router. Configurar proxy para `http://localhost:8000` no `vite.config.ts`. Criar layout base com sidebar (Incidentes, Métricas) e topbar.
- **4.2 — Página de incidentes** `frontend/src/pages/Incidents.tsx`: tabela com colunas: ID, severidade (badge colorido 1–4), tática MITRE, data, status. Paginação. Filtros por severidade e tática. Chamar `GET /api/v1/incidents`.
- **4.3 — Detalhe do incidente** `frontend/src/pages/IncidentDetail.tsx`: timeline vertical de eventos do incidente. Card com análise do agente: severidade, resumo, técnica MITRE (link para attack.mitre.org), ações sugeridas. Card com resultado Sigma como comparação.
- **4.4 — Página de métricas** `frontend/src/pages/Metrics.tsx`: ler `evals/results.json` via endpoint dedicado. Exibir: acerto de gravidade, de tática e de técnica, latência p95. Gráfico de barras agente vs. baseline.
- **4.5 — Análise ao vivo** `frontend/src/pages/Analyze.tsx`: formulário para colar/digitar logs JSON. Botão "Analisar" chama `POST /api/v1/analyze`. Exibe resultado em tempo real com loading spinner.
- **4.6 — Docker Compose** `docker-compose.yml`: adicionar serviço `frontend` (Nginx servindo build estático). Proxy reverso no Nginx para `/api` apontar ao backend. Portas: frontend 3000, backend 8000.
- **4.7 — README completo** `README.md`: GIF de demo (gravar com asciinema ou screen recording), diagrama de arquitetura (Mermaid), instruções "como rodar" com 3 comandos, seção de resultados dos evals, link para demo ao vivo.
- **4.8 — Deploy** Fly.io, Render, Railway ou VPS: fazer deploy da stack Docker Compose completa. Configurar variáveis de ambiente (API keys, DATABASE\_URL). Verificar URL pública acessível.
- **Entrega:** projeto completo com frontend funcional, URL ao vivo, README com GIF e métricas, repositório público pronto para portfólio.

### Marcos de validação

| Marco | Critério de aceite |
| --- | --- |
| M1 — Stack rodando ✅ | `docker compose up` sem erros, logs no banco |
| M2 — Agente funcional ✅ | `/analyze` retorna JSON válido com campos MITRE |
| M3 — Evals passando | Accuracy de severidade acima de 75%; CI verde |
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
│   │   ├── services/         # rag.py, llm.py, sigma_rules.py
│   │   └── main.py
│   ├── scripts/
│   │   ├── generate_logs.py  # 5 cenários sintéticos
│   │   └── seed_mitre.py     # 15 técnicas ATT&CK com embeddings
│   ├── tests/
│   │   ├── test_*.py         # unitários (37 testes passando)
│   │   └── evals/            # golden labels + DeepEval
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                 # React + Vite + Tailwind + Nginx
├── evals/
│   └── results.json          # gerado pelos evals
├── .github/workflows/ci.yml  # lint + testes + build do frontend + evals
├── docker-compose.yml        # Postgres 16 + pgvector, Redis, API, frontend
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

**Decisões em aberto**

- [x] Qual modelo usar? **Decidido:** arquitetura pluggable com factory pattern — suporta Claude (`claude-sonnet-5-5`; o `claude-sonnet-4-20250514` original foi trocado pelo Sonnet atual) e OpenAI (gpt-4o-mini). Configurável via `LLM_PROVIDER` no `.env`.
- [ ] Onde hospedar a demo (Fly.io, Render, Railway ou uma VPS pequena)? Decidir na Fase 4.
- [x] Quando entra o agrupamento automático de eventos em incidentes? **Decidido:** já implementado (`POST /api/v1/analyze/auto`), agrupando por IP, usuário e janela de tempo.
- [x] Incluir parsers de logs reais de firewall no MVP? **Decidido:** não, ficam para v2. O cenário de port scan usa eventos sintéticos com `source="firewall"`. MVP usa 5 cenários: brute force SSH, port scan, phishing, lateral movement, DNS exfiltration.
- [x] Quanto tempo por semana? O roadmap original assumia 10h/semana. Fases 1 e 2 concluídas.
