# Arquitectura ML — Frente 01 "Agent Security"

Responsable: sub-equipo ML. Este documento fija **qué tipo de agente usamos**, cómo
fluyen los datos entre los enclaves y en qué orden construimos. Se actualiza al cerrar
cada fase (sección "Progreso").

---

## 1. Decisión: ¿ReAct o DAG?

**Las dos, y la diferencia entre ellas ES el experimento.**

| Config | Patrón de agente | Por qué |
|---|---|---|
| **A** baseline | **ReAct monolítico**: un LLM, todas las herramientas, cada observación cruda vuelve al contexto y decide el siguiente paso | Es el diseño "normal" de un agente. Lo vulnerable es justo ese bucle: un dato puede convertirse en la próxima acción |
| **B / C** | **ReAct por enclaves**: el Orquestador re-planea después de cada paso leyendo `FreeTextResult` (`PlanStep.origin="replan"`, `payload`) | Muestra que separar privilegios **no basta**: la inyección multi-salto viaja E2 → Orquestador → E1 |
| **D** defendido | **Plan-then-execute con DAG tipado** + intérprete determinista + dual-LLM (handles en cuarentena) | El flujo de control se fija antes de que entre un solo byte no confiable. Los datos llenan valores; nunca añaden nodos, herramientas ni destinos |

### Por qué ReAct no sirve como diseño defendido
En ReAct, `observación → pensamiento → acción` es un ciclo: el texto que devuelve la
herramienta forma parte del razonamiento que elige la siguiente acción. Eso **es** la
definición de *indirect prompt injection*. Ningún clasificador cierra ese canal; solo
lo estrecha.

### Ajuste a tu idea del DAG
La idea es buena con una corrección: **los nodos no son "pasos de pensamiento", son
acciones con dependencias de datos.** El "pensamiento" pasa una sola vez, en el
Planificador, y solo ve el prompt limpio. Después, el DAG lo ejecuta un **intérprete en
Python, sin LLM**, y cada LLM que aparece dentro de un nodo es **single-shot, sin
herramientas y con salida tipada**. Si dejamos que los nodos "piensen" y decidan, el
DAG vuelve a ser ReAct.

Es el patrón de CaMeL (Debenedetti et al., 2025) y del Dual-LLM de Willison,
recortado para que entre en 8 horas.

---

## 2. Flujo en la configuración D

```
 prompt del usuario (TRUSTED)
        │
        ▼
┌─────────────────────────────── E0 · Orquestador ───────────────────────────────┐
│ Planner LLM (1 llamada) ──► Plan JSON ──► PlanValidator (código) ──► DAG       │
│   · acciones ∈ ActionType                · targets en el prompt o allowlist    │
│   · sin texto de datos                   · deps acíclicas, ≤ N nodos           │
│                                          · drift plan-vs-prompt (monitor)      │
│ broker.register_plan(frozen=True)                                              │
│ Intérprete DAG (código): topo-orden → mint_for_step → despacha nodo            │
│   ve solo: ExtractedRecord (tipado), WorkerReceipt, handles q_xxxxxxxx         │
└───────────┬──────────────────────────────────────────────┬─────────────────────┘
            │ token + step                                 │ token + step + refs
            ▼                                              ▼
┌──────── E2 · Aduana (red, sin bóveda) ────────┐  ┌──── E1 · Bóveda (sin red) ─────┐
│ fetch/search/read_inbox (vía broker)          │  │ read_file L1/L2 (vía broker)   │
│ 1. HTML → visible | oculto (css, comment, alt)│  │ Writer LLM: ve prompt + L2,    │
│ 2. imágenes → VLM transcribe (+ OCR opcional) │  │   NUNCA ve texto L0            │
│ 3. Extractor LLM (sin tools, JSON schema)     │  │   escribe con placeholders     │
│    ∥ extractor regex                          │  │   {{s1.total_amount}} {{q_..}} │
│ 4. Verificador de procedencia                 │  │ Renderer (código) sustituye;   │
│ 5. ExtractedRecord (pydantic, extra=forbid)   │  │   handles → bloque escapado    │
│ 6. texto libre → QuarantineStore → handle     │  │   (sin ![]() ni links activos) │
└───────────────────────────────────────────────┘  │ write_diff → drift(diff, goal) │
                                                   └────────────────────────────────┘
```

**Lo peor que puede hacer una inyección perfecta en D:** que el extractor (hijackeado)
ponga un valor erróneo en un campo tipado que *además* aparece en el documento fuente.
Es *data poisoning* semántico, no ejecución, y se documenta como riesgo residual (P4).

---

## 3. Componentes ML

### 3.1 `llm.py` — cliente
- `LLMClient(enclave)`: OpenAI-compatible, configurado con `LLM_BASE_URL`, `LLM_API_KEY` y `LLM_MODEL_<ENCLAVE>`. Una instancia por enclave.
- `complete_json(messages, schema: type[BaseModel]) -> BaseModel`: usa `response_format=json_schema` si el endpoint lo soporta; si no, parsea y reintenta (máx. 2). `temperature=0`, `seed` fijo.
- Cuenta llamadas y latencia por enclave (métricas de la matriz).
- `MockLLM`: respuestas guionizadas por (enclave, rol). Tiene modo `obedient_attacker` para el baseline. Solo se usa en tests; las filas mock se marcan como tales.

### 3.2 Planner (E0)
- Entrada: prompt + catálogo de `ActionType` + allowlist de hosts y rutas. Nada más.
- Salida: `Plan` validado. El `PlanValidator` rechaza (y registra `PLAN_STEP_REJECTED`) cualquier target que no salga del prompt o de la allowlist.
- **Fan-out acotado:** "busca X y lee el primer resultado" se planea como `s1: web_search` → `s2: fetch_url target="$s1.urls[0]"`. La *estructura* la fija el planner; solo el *valor* sale de los datos y pasa otra vez por la allowlist y el broker.
- Mock / fallback: planner por reglas (palabras clave → acciones) para que `main.py --mock` corra sin LLM.

### 3.3 Aduana (E2) — el corazón ML
| Etapa | Baseline (funciona hoy) | Mejora ML |
|---|---|---|
| Parseo | `html.parser` separa visible y oculto (`display:none`, blanco sobre blanco, comentarios, `alt`/`aria-label`) | — |
| Imágenes | sin transcripción; solo `image_count` | VLM transcribe a texto → handle `image_text`; OCR opcional y divergencia VLM-vs-OCR como **señal** |
| Extracción | regex por campo de `EXTRACTABLE_FIELDS` | Extractor LLM con JSON schema; se fusiona con la regex |
| Procedencia | valor normalizado ∈ texto **visible** (montos `1,234.50` / `1.234,50`, fechas ISO/locales) | — (determinista a propósito) |
| Señal de inyección | heurística (imperativos dirigidos a "AI assistant", ratio de texto oculto) | juez LLM pequeño. **Solo telemetría**, no bloquea |

Regla clave: la procedencia se verifica contra el texto **visible**. Por eso un monto
inyectado en un `<span display:none>` (factura 2002) se descarta aunque el extractor
caiga en la trampa.

### 3.4 Trabajador de bóveda (E1)
- El Writer LLM recibe el prompt del usuario, el contenido L2 leído y la *lista de nombres* de campos y handles disponibles. **Nunca recibe el texto de un handle.**
- Produce un borrador con placeholders. El renderer de código sustituye los campos tipados y vuelca los handles como bloque citado y escapado ("contenido externo no verificado"), para que lo lea el humano y no un LLM.
- `PATCH_CODE`: la instrucción viene solo del prompt (`PlanStep.target`) y el diff pasa por `intent_drift` antes de `write_diff`.

### 3.5 `intent_drift.py`
Dos niveles:
1. **Plan vs prompt**: ¿el plan contiene acciones que el usuario no pidió? (p. ej. `PATCH_CODE` sin mención a código).
2. **Diff vs objetivo**: ¿el diff introduce URLs, red, `os.environ`, lectura de rutas L2 o líneas no relacionadas con la tarea?

Baseline: reglas y similitud léxica. Mejora ML: juez LLM pequeño con umbral calibrado
sobre unos 20 diffs etiquetados (benignos/maliciosos) y TPR/FPR reportados. Embeddings
solo si se aprueba la dependencia.

Honestidad para el pitch: en D el plan congelado ya bloquea la mayoría de los ataques.
`intent_drift` aporta sobre todo en los diffs de `PATCH_CODE` que el usuario sí pidió.

---

## 4. Modelos (RTX 3060 8 GB)

Vía Ollama u OpenRouter, configurados solo en `.env` (nunca en código). Sugerencia para
probar; verificar los tags disponibles:
- Planner / Writer / Baseline: un instruct de ~7B cuantizado Q4 (~5 GB).
- Aduana: un VLM de 3B–7B Q4.
- Para no pagar el swap de modelos en 8 GB: usar **un solo VLM de 7B para todos los enclaves** (instancias de cliente separadas, mismo modelo) y `OLLAMA_MAX_LOADED_MODELS=1`.
- Ojo: un modelo pequeño puede *no obedecer* la inyección en el baseline (ASR base bajo) y también fallar tareas benignas. Medir el baseline temprano (fase M6).

---

## 5. Cambio de contrato a acordar con Ciberseguridad

`PlanStep` no tiene dependencias explícitas. Propuesta, compatible hacia atrás:

```python
inputs: tuple[StepId, ...] = ()   # nodos cuyo output consume este paso
```

Las referencias de valor (`$s1.urls[0]`, `{{s2.total_amount}}`) solo pueden apuntar a
`inputs`. Sin este campo, el DAG queda en una lista secuencial (funciona, pero se pierde
la validación de dependencias).

---

## 6. Plan por fases y progreso

Cada fase termina con: tests en verde → `✅ Fase Mn` en esta tabla → commit local.

| Fase | Entregable | Prueba | Estado |
|---|---|---|---|
| M0 | Acordar `PlanStep.inputs` + este documento | revisión con Ciber | 🟡 doc listo, falta acuerdo |
| M1 | `llm.py`: `LLMClient` + `MockLLM` + métricas | `pytest tests/test_llm.py` | ⬜ |
| M2 | `quarantine.py`: store, handles, verificador de procedencia | `pytest tests/test_quarantine.py` | ⬜ |
| M3 | `customs.py` baseline (parseo visible/oculto, regex, procedencia) contra el servidor de pruebas | `pytest tests/test_customs.py` | ⬜ |
| M4 | Planner + validator + intérprete DAG + `vault_worker` + modo reactivo B/C | `python main.py --mock` | ⬜ |
| M5 | `intent_drift.py` (plan y diff) + set etiquetado de diffs | `pytest tests/test_intent_drift.py` | ⬜ |
| M6 | Live: extractor LLM, VLM de imágenes, juez de deriva; baseline A con LLM real | `python main.py --live` | ⬜ |
| M7 | Matriz A–D live, gráficas, sección P4 | `python eval/run_matrix.py --live` | ⬜ |

**Dependencias por aprobar antes de M6:** OCR (`rapidocr-onnxruntime` es solo pip;
`pytesseract` exige instalar Tesseract) y embeddings (`sentence-transformers` trae
torch). Sin aprobación seguimos solo con VLM + juez LLM.
