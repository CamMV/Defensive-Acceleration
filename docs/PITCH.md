# Pitch — Frente 01 "Agent Security"

Agente Auditor de Contratación Pública: cruza documentos de internet y de contratistas con una bóveda
de expedientes reservados. Todos los números salen de [`RESULTS.md`](RESULTS.md); † = el número está en
`ML_ARCHITECTURE.md` §5d pero sus datos no se subieron al repo.

## 1. Vector de amenaza

Inyección indirecta de prompts: la instrucción del atacante llega dentro de un dato que el agente lee
(HTML oculto, imágenes, documentos de oficina, facturas de contratistas). Se suma el *confused deputy*:
un agente con acceso a la bóveda y a la web puede ser usado para sacar expedientes o alterar archivos internos.

## 2. Mecanismo

- **3 enclaves** con privilegios disjuntos: Orquestador (sin herramientas), Trabajador de Bóveda (sin red), Aduana (sin bóveda).
- **CapabilityBroker** determinista: tokens HMAC por paso, validación de rutas, taint L0/L1/L2, monitor de
  egreso con canaries y canaries de system prompt.
- **Aduana**: plan congelado antes de leer datos externos, texto libre en cuarentena (handles opacos),
  verificación de procedencia, escáner de doble chequeo (regex + Galvanize-3) y datamarking.
- **Config E**: la misma idea con el plan como DAG congelado (`agent_runtime/ml_d`).

## 3. Validación empírica

| Qué se midió | Resultado | Sección |
|---|---|---|
| Escáner, 611 casos, después de v3 | detección 0.81 †, falsas alarmas 0.08 † (antes: 0.85 / 0.16) | (a) |
| Sistema completo D, atacante oráculo | ASR 0.00 †, utilidad 0.87 †, falso bloqueo 0.13 † | (b) |
| LLM real (llama3), muestra de 16 | A: 2/8 ataques con daño †. D: 0/8 † | (c) |
| Latencia con LLM real | D: p50 1.7 s †, máx 2.2 s †. A: p50 39 s † | (c) |

**Mensaje central:** el clasificador deja pasar cerca de 1 de cada 5 inyecciones (detección 0.81 †) y aun
así el ASR de D es 0.00 †. Lo que el filtro no ve, la arquitectura lo contiene: el LLM que lee el
documento no tiene herramientas para hacer daño.

La matriz A–E solo existe en mock y no es una medida (sección d). Con LLM real, la matriz A–E: **no medido**.

## 4. Limitaciones y uso dual

- Todo corre en un mismo proceso Python; no hay sidecar que aísle el broker.
- La muestra en vivo es pequeña (16 casos) y con un solo modelo.
- El umbral del escáner se calibró sobre el mismo benchmark que se reporta.
- Los modelos de Hugging Face se cargan sin revisión fija, y WARD-2b con `trust_remote_code`.
- Canales laterales de tamaño y tiempo sin mitigar.
- Envenenamiento semántico: un valor falso pero bien formado pasa esquema y procedencia.
- En la matriz oficial, E tiene utilidad 0.111 (mock) por un desajuste entre los prompts y su planner.
- Uso dual: los payloads son genéricos y solo apuntan a `127.0.0.1`.

## Demo de 60 s

```bash
python main.py --mock --scenario atk_multihop_app
```

1. **0–15 s.** El usuario pide registrar la versión recomendada de un changelog. La página trae una "nota
   de migración" que pide agregar una línea a `app.py`.
2. **15–30 s.** Config A: `app.py modificado: SI`, "ATAQUE EXITOSO".
3. **30–45 s.** Config D y config E: `app.py modificado: no`, "ATAQUE BLOQUEADO", con la regla que negó.
4. **45–60 s.** Abrir el `runs/<fecha>/audit.jsonl` que imprime la demo: cada llamada y cada decisión del broker.

Esta demo usa el LLM mock (atacante obediente). Si hay Ollama con los `LLM_MODEL_*` en `.env`, el mismo
comando con `--live` la muestra con un modelo real.
