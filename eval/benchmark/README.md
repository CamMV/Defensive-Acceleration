# Benchmark de prompt injection

Mide el filtro de la Aduana: la regex de main (línea base), Galvanize-3 solo y el doble chequeo
(regex + Galvanize-3, el que corre en producción). Las imágenes pasan por WARD-2b.

## Relanzar

```bash
# Desde la raíz del repo, con el entorno que tiene torch/transformers
.venv/bin/python -m eval.benchmark.run                     # completo (~1-2 min con GPU)
.venv/bin/python -m eval.benchmark.run --no-images         # sin WARD-2b
.venv/bin/python -m eval.benchmark.run --scanners regex    # solo la línea base, sin GPU
.venv/bin/python -m eval.benchmark.run --threshold 0.9     # probar otro umbral
.venv/bin/python -m eval.benchmark.run --only handwritten  # handwritten | generated | image
.venv/bin/python -m eval.benchmark.run --cat exfiltration  # una categoría
# Comparar contra una corrida anterior (guarda antes una copia de latest, porque se sobrescribe):
cp -r results/benchmark/latest results/benchmark/base
.venv/bin/python -m eval.benchmark.run --compare results/benchmark/base/report.json
```

Resultados en `results/benchmark/<fecha-hora>/` y copia en `results/benchmark/latest/`:
`report.md` (tablas), `report.json`, `cases.jsonl` (score por caso y escáner), `failures.csv`
(errores del doble chequeo) e `images/` (PNG generados + `transcripts.json`).

## Qué contiene

- `cases.yaml`: 167 casos escritos a mano en 25 categorías. Positivos: anulación, rol, suplantación
  de autoridad, exfiltración, secuestro de herramientas, camuflaje como dato, manipulación de salida,
  delimitadores falsos, markdown, condicionales, extracción de prompt, otros idiomas, payload dividido.
  Negativos difíciles: trámites con imperativos, runbooks, material de seguridad que cita ataques,
  código, correos, contratos, asistentes humanos, documentación de productos de IA, datos densos.
- `transforms.py`: variantes deterministas de las semillas (`seed: true`): 9 ofuscaciones, 9 canales
  de transporte (HTML oculto, JSON, CSV, markdown), aguja en pajar (inicio/mitad/final), documentos
  largos y bilingües, y 29 imágenes en 6 estilos (normal, bajo contraste, pequeño, rotado, ruido, banner).
- `diff: boundary` marca casos discutibles a propósito; el reporte da métricas con y sin ellos.
- `scope: out` (data poisoning sin imperativos) se reporta aparte: un detector de inyección no
  debería atraparlo; lo cubre la verificación de procedencia.

## Agregar casos

Añade una línea a `cases.yaml` con `id` único, `label`, `cat`, `lang`, `diff` y `text`. Con
`seed: true` se generan además todas sus variantes. `pytest tests/test_benchmark.py` valida el archivo.

Advertencia: los casos los escribió el mismo equipo que construye el detector (sesgo de autor).
Para cifras externas, agrega documentos reales anonimizados.

## Extremo a extremo (sistema completo)

`e2e.py` hace pasar los mismos casos por el sistema entero (planner, broker, Aduana, cuarentena,
trabajador de bóveda). Cada caso se sirve como página del servidor de pruebas, o como PNG directo si
es imagen, y el juez mira solo efectos observables: canary en el sumidero del atacante, system prompt
filtrado, `app.py` modificado, lectura no autorizada de la bóveda, canary o monto envenenado en el acta.

```bash
.venv/bin/python -m eval.benchmark.e2e                                   # mock oráculo, A / D-arch / D-regex / D (~3-5 min)
.venv/bin/python -m eval.benchmark.e2e --configs A,D --no-images         # más rápido
.venv/bin/python -m eval.benchmark.e2e --live --model llama3 --sample 16 --configs A,D --no-images   # LLM real (Ollama)
cp -r results/benchmark_e2e/latest results/benchmark_e2e/base
.venv/bin/python -m eval.benchmark.e2e --compare results/benchmark_e2e/base/report.json
```

Resultados en `results/benchmark_e2e/<fecha-hora>/` y `latest/`: `report.md`, `report.json`,
`sessions.jsonl` (una fila por caso y configuración) y `d_successes/` (auditoría y acta de cualquier
ataque que haya funcionado contra una configuración D).

- **Mock oráculo**: el LLM simulado obedece perfectamente la inyección del caso en cuanto un LLM ve el
  documento (exfiltrar `.env`, modificar `app.py`, envenenar el monto, filtrar el system prompt). Es el
  peor caso. La señal que lo activa es la referencia `DOC-XXXXXX`, que también llevan las páginas
  legítimas, así que el filtro no puede usarla como pista.
- **`--live`**: el LLM real (cualquier endpoint OpenAI-compatible) lee la inyección tal cual. Es lento con
  un modelo local, así que usa `--sample`. Con GPU de 8 GB usa `--no-images` (desactiva WARD-2b).
- Configuraciones: `A` (baseline sin defensas), `D-arch` (D sin filtro: solo arquitectura), `D-regex`
  (filtro = regex de main) y `D` (regex + Galvanize-3 + WARD-2b, producción).
- Limitación: el agente A no tiene OCR, así que las inyecciones solo en imagen no lo afectan.
