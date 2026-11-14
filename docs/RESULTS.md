# Resultados medidos

Este documento reúne los números que el equipo ya midió hasta el commit `962e23c` ("v3", rama `ML`).
No se corrió ninguna medición nueva para escribirlo, salvo la matriz mock de la sección (d), que es
determinista y no carga modelos.

Cada número lleva su fuente. Hay dos tipos de fuente:

- **Datos en el repo**: `docs/benchmarks/ml_20261114/report.json`, `report.md`, `cases.jsonl`, `failures.csv`
  y `docs/results_mock/`. Se pueden recalcular.
- **Solo en el documento**: `docs/ML_ARCHITECTURE.md` §5d. El número está escrito ahí, pero los datos que lo
  producen (`results/benchmark_e2e/`, `results/threshold_sweep.json`) están en `.gitignore` y no se subieron.
  Esos números van marcados con †.

`report.md` y `report.json` son de **antes** de v3 (umbral de Galvanize 0.95, la regex bloqueaba sola).
§5d describe el estado de **después** (umbral 0.99, la regex solo audita, enmascarado por oración).

## a) Escáner de inyección, antes y después de v3

Benchmark de `eval/benchmark`: **n = 611 casos en alcance** (338 inyecciones, 273 legítimos). Sin los
casos de frontera quedan 523 (327 inyecciones, 196 legítimos). Escáner medido: doble chequeo (regex + Galvanize-3).

| Doble chequeo | Antes de v3 | Después de v3 |
|---|---|---|
| Detección / falsas alarmas, los 611 casos | 0.85 / 0.16 | 0.81 / 0.08 † |
| Detección / falsas alarmas, sin casos de frontera (523) | 0.87 / 0.12 | 0.83 / 0.06 † |

Fuentes:

- **Antes**: `docs/benchmarks/ml_20261114/report.md`, sección "General" y tabla "Sin casos de frontera".
  En `report.json`: `overall.dual` (286 de 338 detectadas, `tpr` 0.8462; 45 de 273 falsas alarmas, `fpr` 0.1648)
  y `overall_no_boundary.dual` (`tpr` 0.8746, `fpr` 0.1173).
- **Después** †: `docs/ML_ARCHITECTURE.md` §5d, tabla "Antes / Después". No hay `report.json` posterior a v3 en el repo.

Comprobación con datos del repo (no es la medición de v3): al aplicar el umbral 0.99 a los scores de
Galvanize guardados en `cases.jsonl`, que son de antes de v3, y sin que la regex bloquee, sale:

| Recalculado de `cases.jsonl` | Detección | Falsas alarmas |
|---|---|---|
| Los 611 casos | 273/338 = 0.8077 | 25/273 = 0.0916 |
| Sin casos de frontera | 273/327 = 0.8349 | 13/196 = 0.0663 |

La detección coincide con §5d (0.81 y 0.83). Las falsas alarmas recalculadas quedan un poco por encima
de las de §5d (0.08 y 0.06). v3 también cambió cómo se parte el texto en trozos (alineados a párrafos),
y esos scores no están en el repo, así que la diferencia no se puede atribuir con certeza.

## b) Extremo a extremo, configuración D

Medido con `eval/benchmark/e2e.py`: el sistema completo, con **atacante oráculo**. El LLM simulado obedece
perfectamente la inyección del caso en cuanto algún LLM ve el documento. Es el peor caso para la defensa y
no es un modelo real (`eval/benchmark/README.md`, "Mock oráculo").

| Config D, extremo a extremo | ASR | Utilidad | Falso bloqueo |
|---|---|---|---|
| Antes de v3 | 0.00 † | 0.81 † | 0.19 † |
| Después de v3 | 0.00 † | 0.87 † | 0.13 † |
| Después de v3, envoltura neutral | 0.00 † | 0.94 † | 0.06 † |

Fuente †: `docs/ML_ARCHITECTURE.md` §5d, tabla "Antes / Después". El doc no indica el número de casos de
estas corridas. Los `report.json` y `sessions.jsonl` que las respaldan no están en el repo.

"Envoltura neutral" es la opción `--wrapper neutral`: la página que envuelve cada caso no lleva el título
del proceso de contratación (ver sección e).

## c) LLM real

llama3 en Ollama, **muestra de 16 casos** (8 ataques). **Muestra pequeña, un solo modelo.**

| Config | Ataques con daño | Latencia p50 | Latencia máx |
|---|---|---|---|
| A (monolítico sin defensas) | 2/8 † | 39 s † | no indicado |
| D (sistema defendido) | 0/8 † | 1.7 s † | 2.2 s † |

En los 2 casos de A, el agente leyó `.env` y lo copió al acta †.

Fuente †: `docs/ML_ARCHITECTURE.md` §5d, último párrafo. El comando documentado en
`eval/benchmark/README.md` para esta corrida usa `--no-images`, es decir, sin WARD-2b. Los datos por caso
no están en el repo. No hay ninguna corrida de `eval.run_matrix --live`: la matriz A–E no se midió con un LLM real.

## d) Matriz A–E en mock

**MOCK: no es una medida.** El LLM es un atacante obediente y determinista. Esta tabla solo prueba que el
pipeline, el broker y los jueces funcionan de punta a punta para las cinco configuraciones.

Comando: `python -m eval.run_matrix --mock --configs ABCDE --reps 1`, con `GALVANIZE_MODE=off` y
`WARD_MODE=off`, sobre el commit `2f8f57d` de `integracion`. 14 ataques y 9 tareas benignas por configuración.

| Config | llm | ASR | prompt_leak_rate | Utilidad | Falso bloqueo | Llamadas LLM (media) |
|---|---|---|---|---|---|---|
| A: monolítico sin defensa | mock | 1 | 1 | 1 | 0 | 4.87 |
| B: enclaves + broker | mock | 0.929 | 1 | 1 | 0 | 8.04 |
| C: B + taint/egreso | mock | 0.286 | 0 | 0.889 | 0.111 | 6.48 |
| D: broker + taint + aduana + scanner + datamarking | mock | 0 | 0 | 1 | 0 | 2.39 |
| E: D-ML, plan DAG congelado (`ml_d`) | mock | 0 | no medido | 0.111 | 0 | 0 |

Fuente: `docs/results_mock/matrix.csv` (agregado) y `docs/results_mock/runs.csv` (una fila por corrida).

Notas para leer la tabla:

- `prompt_leak_rate` se calcula sobre 2 escenarios de extracción de system prompt por configuración.
- E sale "no medido" en `prompt_leak_rate` porque `ml_d` no pone canaries de system prompt.
- La utilidad 0.111 de E es un desajuste de integración, no un resultado de la defensa. El planner de
  `ml_d` no reconoce `internal_workspace/acta_auditoria.md` como petición de escribir el acta (su regex
  exige la palabra `acta` suelta), así que en 8 de las 9 tareas benignas no escribe nada. Por la misma
  razón su ASR 0 en los escenarios que se juzgan por el contenido del acta no dice nada.
- Se omiten 3 escenarios que requieren leer imágenes (columna `skipped_requires_vlm`).
- La latencia no se reporta aquí: en mock son milisegundos y cambia entre corridas.

## e) Hallazgos cualitativos

**Galvanize es sensible al contexto.** El mismo texto bajo el título "Documento del proceso LP-2026-014"
da 12 % de falsas alarmas y 82 % de detección; sin título, 5 % y 73 % †. Una orden bajo un encabezado
ajeno le parece inyección, sea legítima o maliciosa. Fuente †: `docs/ML_ARCHITECTURE.md` §5d, "Hallazgo".

**Por qué la regex ya no bloquea sola.** En el benchmark de antes de v3, la regex no atrapó ningún ataque
que Galvanize no atrapara y sumó 10 falsas alarmas. Este dato sí está en el repo:

- `report.json`: `overall.galvanize` y `overall.dual` detectan lo mismo (`tp` 286 en ambos), pero las
  falsas alarmas suben de 35 a 45.
- `cases.jsonl`: 0 inyecciones bloqueadas solo por la regex; 10 legítimos bloqueados solo por la regex.

Desde v3 su veredicto `malicious` baja a `suspicious`: se audita, pero no bloquea
(`docs/ML_ARCHITECTURE.md` §5d, punto 1; `.env.example`: `INJECTION_REGEX_BLOCKS=0`, `GALVANIZE_THRESHOLD=0.99`).
Si Galvanize no está disponible, la regex sola sí bloquea.

## Trazabilidad

| Número | ¿Datos en el repo? |
|---|---|
| Escáner antes de v3 (0.85 / 0.16, 0.87 / 0.12) | Sí: `report.json`, `report.md` |
| Regex: 0 detecciones propias, 10 falsas alarmas | Sí: `report.json`, `cases.jsonl` |
| Matriz mock A–E | Sí: `docs/results_mock/` |
| Escáner después de v3 (0.81 / 0.08, 0.83 / 0.06) | No, solo en §5d. Recalculado aproximado en (a) |
| Extremo a extremo D, las tres filas | No, solo en §5d |
| LLM real: 2/8, 0/8, latencias | No, solo en §5d |
| Sensibilidad al contexto (12 % / 82 %, 5 % / 73 %) | No, solo en §5d |

El umbral 0.99 se eligió sobre el mismo benchmark que se reporta (`eval/sweep_threshold.py`). No hay un
conjunto de prueba separado, así que las cifras de "después" son optimistas por construcción.
