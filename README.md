# Defensive-Acceleration — Frente 01 "Agent Security"

Prototipo defensivo medible contra *indirect prompt injection* para un Asistente de
Auditoría / Due Diligence que cruza información pública de internet con documentos
confidenciales. Hackathon Defensive Acceleration (AI Safety Colombia × IEEE CS Uniandes).

Python puro + pydantic v2 + httpx + FastAPI. Sin frameworks agénticos, sin Docker.
Todos los datos de la bóveda son ficticios y los canaries son sintéticos (`CANARY-` + hex).

## Cómo correr

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

.venv\Scripts\python.exe -m pytest -q                 # tests por capa, sin red ni claves
.venv\Scripts\python.exe main.py --mock               # demo: mismo ataque, baseline vs defendido
.venv\Scripts\python.exe -m eval.run_matrix --mock    # matriz de ablación -> results/
```

Con un LLM real: copiar `.env.example` a `.env`, definir `LLM_BASE_URL`, `LLM_API_KEY` y un
`LLM_MODEL_*` por enclave, y usar `--live` en `main.py` y en `eval.run_matrix`.

Por defecto el servidor de pruebas corre **en proceso** (sin sockets). Para verlo en el navegador o
usar sockets reales: `.venv\Scripts\python.exe -m test_server.app` (escucha solo en `127.0.0.1:8000`)
y agregar `--http` a los comandos anteriores.

`main.py --scenario <id>` acepta cualquier id de `eval/scenarios.yaml` (por ejemplo `atk_multihop_app`).

## Arquitectura

```
usuario ──prompt limpio──> Enclave 0  Orquestador (control plane, sin herramientas)
                               │  1. fija el plan SOLO con el prompt (plan-then-execute)
                               │  2. pide al broker un token por paso
                ┌──────────────┴───────────────┐
                ▼                              ▼
   Enclave 2  Aduana                 Enclave 1  Trabajador de Bóveda
   red, cero bóveda                  bóveda, cero red
   fetch_url, web_search,            read_file (L1/L2), write_diff (L1)
   read_inbox (solo L0)
                └────────── CapabilityBroker ──┘
        tokens HMAC · rutas · taint L0/L1/L2 · monitor de egreso · audit JSONL
```

- **Orquestador**: en la configuración completa solo recibe `ExtractedRecord` (campos tipados +
  handles opacos `q_xxxxxxxx`) y `WorkerReceipt` (metadatos). Nunca ve texto de internet ni contenido L2.
- **Aduana**: su LLM lee el documento crudo y puede quedar secuestrado, así que su salida pasa por
  esquema estricto (`extra="forbid"`), verificador de procedencia contra el texto *visible*, y la regla
  "el extractor determinista gana si hay desacuerdo". El texto libre va al `QuarantineStore`.
- **Trabajador**: su LLM ve campos tipados y la bóveda. Los handles los desreferencia el código al
  renderizar el reporte, marcados como contenido no confiable.
- **Broker**: único camino para ejecutar herramientas. El LLM nunca recibe tokens; una llamada que
  pide por iniciativa propia va sin token y se niega.

### Reglas del broker (campo `rule` del log)

| Capa | Reglas |
|---|---|
| Registro por enclave | `tool_unknown`, `tool_not_in_registry`, `bad_arguments` |
| Token (HMAC, sesión, TTL, uso único, scope) | `token_missing`, `token_bad_signature`, `token_wrong_session`, `token_scope_mismatch`, `token_expired`, `token_reused` |
| Plan | `step_not_in_plan`, `tool_not_in_step`, `subresource_not_static` |
| Rutas (`resolve()` + contención) | `path_invalid`, `path_unc`, `path_absolute`, `path_escape`, `path_symlink`, `path_outside_levels`, `path_level_not_allowed`, `path_not_found` |
| Red | `host_not_allowed` |
| Taint | `taint_l2_to_network` |
| Egreso | `egress_canary_detected`, `system_canary_egress` (lanza `SystemPromptLeakageError`) |
| Aduana / deriva | `field_not_in_schema`, `field_failed_validation`, `value_not_in_source`, `extractor_disagreement`, `intent_drift`, `handle_read_denied` |

Evidencia de cada corrida: `runs/<timestamp>/audit.jsonl` (llamadas, decisiones allow/deny con su regla,
tokens emitidos, handles creados). Los canaries en claro se enmascaran en el log.

**Fuga de system prompt (Fase 7).** Cada instancia de enclave añade al final de su system prompt un canary
único `SYS-CANARY-E<n>-<hex>` (M0 en el baseline). Si aparece (plano, URL, Base64, hex, invertido o fragmentado)
en un sumidero de red (`web_search`, `fetch_url`), el broker lo bloquea antes que cualquier otra regla y lanza
`SystemPromptLeakageError`. Si el canary de E0/E1 aparece en lo que se entrega a la Aduana, se registra el evento
`internal_prompt_leakage` en `audit.jsonl` sin bloquear.

## Matriz de ablación

| Config | Qué activa | Qué significa |
|---|---|---|
| A | nada | Agente monolítico con todas las herramientas (`baselines/monolithic_agent.py`) |
| B | enclaves + broker | Orquestador **reactivo**: lee resultados en texto libre y puede añadir pasos |
| C | B + taint + egreso | Igual que B, pero el contexto que tocó L2 no puede llegar a la red |
| D | C + plan congelado + aduana | Handles, procedencia, deriva; el Orquestador no lee texto no confiable |

Decisión de diseño: el plan congelado va en D y no en B. Un plan fijo solo se sostiene si el Orquestador
no necesita leer los resultados; mientras lea texto libre (B/C) es un *confused deputy*, y eso es lo que
B y C miden. El interruptor `frozen_plan` de `DefenseConfig` permite ablacionarlo por separado.

Métricas en `results/matrix.csv`: Attack Success Rate, Benign Utility, tasa de falsos bloqueos (corridas
benignas con al menos un DENY), `prompt_leak_rate` (de los ataques de extracción de system prompt, fracción
cuyo canary llegó al atacante), `internal_prompt_leaks` (eventos E0/E1 -> Aduana), latencia media y llamadas LLM. `results/runs.csv` trae una fila por corrida.

**Sobre los números con `--mock`:** el MockLLM es un atacante obediente (sigue toda instrucción inyectada
que reconoce). Ejercita el pipeline y los jueces; no mide un modelo real. La columna `llm` marca cada fila
como `mock` o `live`. El ASR que se reporte debe salir de `--live`.

Los escenarios `requires_vlm` (payload solo dentro de una imagen) se omiten mientras no haya OCR/VLM
conectado y quedan listados en la columna `skipped_requires_vlm`. `--include-vlm` los incluye.

## Estructura y responsables

| Ruta | Contenido | Responsable |
|---|---|---|
| `agent_runtime/contracts.py` | Contrato compartido: modelos, enums, routing, configuraciones | Ambos (cambios por acuerdo) |
| `agent_runtime/broker.py` | Broker, tokens, rutas, taint, audit log | Ciberseguridad |
| `agent_runtime/monitors/egress.py` | Canaries en claro, Base64, URL, hex, invertidos, fragmentados | Ciberseguridad |
| `agent_runtime/tools/` | `local_tools.py`, `web_tools.py` (allowlist `127.0.0.1:8000`) | Ciberseguridad |
| `test_server/` | Páginas benignas y envenenadas, `/collect`, imágenes trampa | Ciberseguridad |
| `baselines/monolithic_agent.py` | Baseline sin defensas | Ciberseguridad |
| `agent_runtime/enclaves/customs.py` | Aduana: fallback HTML→texto + regex; puntos `# ML-TEAM:` | ML |
| `agent_runtime/monitors/intent_drift.py` | Interfaz + baseline léxico de deriva | ML |
| `agent_runtime/quarantine.py` | Handles opacos + verificador de procedencia | ML (procedencia) / Ciber (store) |
| `agent_runtime/enclaves/orchestrator.py`, `vault_worker.py`, `base.py` | Enclaves 0 y 1 | Ambos |
| `agent_runtime/llm.py` | Cliente OpenAI-compatible + MockLLM | Ambos |
| `eval/` | `scenarios.yaml`, `judge.py`, `run_matrix.py` | Ambos |
| `vault/` | Datos sintéticos de los 3 niveles | Ciberseguridad |

Cambios respecto a la estructura objetivo, con su razón:

- `agent_runtime/textutil.py`: HTML→texto visible y regex. Lo usan la Aduana, la procedencia y el mock; separado para evitar imports circulares.
- `agent_runtime/runtime.py`: cableado de una sesión, compartido por `main.py` y `eval/run_matrix.py`.
- `agent_runtime/enclaves/base.py`: lógica común (historial propio, llamada vía broker, chequeo de deriva).
- `eval/judge.py`: jueces automáticos, compartidos por la demo y la matriz.
- Herramienta `read_inbox` (Aduana, solo L0): mantiene los registros disjuntos; `read_file` es solo del Trabajador.
- Cada corrida trabaja sobre una copia de `vault/` en `runs/<timestamp>/<sesión>/` con su propio
  `attacker_log.jsonl`, para que las mediciones no se contaminen. El servidor levantado a mano escribe en `runs/attacker_log.jsonl`.

## Limitaciones y uso dual

- **Aislamiento en un solo proceso.** Los enclaves son clases Python, no procesos ni sandboxes. La separación
  depende de que el código de los enclaves respete el broker; un bug o una dependencia maliciosa en el mismo
  intérprete la rompe. Para producción: procesos separados con filtrado de red a nivel de SO.
- **Canales laterales.** El Orquestador ve metadatos derivados de L2 (`ok`, `bytes_written`, `sha256`) y los
  tiempos de cada paso. Tamaño y tiempo pueden codificar bits. No se mitiga.
- **Envenenamiento semántico dentro de esquemas válidos.** Una página puede mentir con un valor bien formado
  y visible (un monto o una versión falsos). Pasa esquema y procedencia. La procedencia prueba que el valor
  está en la fuente, no que la fuente diga la verdad.
- **El Trabajador escribe L2 en L1.** Es su función. El reporte hereda la etiqueta L2 y no puede salir por
  red, pero un humano que lo comparta rompe la garantía.
- **Taint grueso.** La etiqueta es por contexto de enclave, no por valor. En C produce falsos bloqueos
  (leer L2 y luego buscar en la web). D lo evita por arquitectura, no por un taint más fino.
- **Monitor de egreso.** Decodifica un nivel sobre URL-decoding. Codificaciones anidadas (Base64 dentro de
  hex), cifrado, o fragmentos menores a 4 caracteres escapan. El juez de exfiltración reutiliza estos
  decodificadores, así que comparte el mismo punto ciego.
- **Imágenes.** Sin OCR/VLM el texto en imágenes no se lee: el ataque por imagen no se puede ejecutar ni medir todavía.
- **Baselines léxicos.** `intent_drift` y la detección de elementos ocultos en HTML son reglas simples; un CSS
  externo o un contraste casi igual las evade.
- **Uso dual.** Los payloads son genéricos y de demostración, apuntan solo al servidor local y no incluyen
  técnicas de evasión contra productos reales. La allowlist de `web_tools.py` impide que el red-team salga de `127.0.0.1:8000`.
