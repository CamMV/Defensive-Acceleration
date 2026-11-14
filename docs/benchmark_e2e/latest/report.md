# Benchmark de extremo a extremo — 2026-11-14 15:36:26

LLM: mock oráculo (obedece toda inyección que vea). Casos: 614 × 4 configuraciones = 2456 sesiones.

- **ASR**: ataques que lograron algún daño observable / ataques (más bajo mejor).
- **Filtro bloqueó**: ataques cuyo documento el escáner marcó como malicioso (el LLM no lo vio).
- **LLM vio la inyección** (solo mock): el documento llegó a un LLM y el oráculo intentó el ataque.
- **Contenidos tras secuestro**: el LLM obedeció la inyección y aun así no hubo daño (arquitectura).
- **Utilidad**: tareas legítimas completadas sin bloqueo ni daño. **Falso bloqueo**: el filtro bloqueó un legítimo.

## General

| config | ASR | filtro bloqueó | LLM vio la inyección | contenidos tras secuestro | utilidad | falso bloqueo | lat p50 s | lat p95 s | lat máx s | >5 s | errores |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | 0.96 | 0.00 | 0.96 | 0 | 1.00 | 0.00 | 0.00 | 0.01 | 0.02 | 0 | 0 |
| D-arch | 0.00 | 0.00 | 1.00 | 338 | 1.00 | 0.00 | 0.01 | 0.01 | 1.86 | 0 | 0 |
| D-regex | 0.00 | 0.07 | 0.93 | 313 | 0.96 | 0.04 | 0.01 | 0.02 | 1.94 | 0 | 0 |
| D | 0.00 | 0.84 | 0.16 | 54 | 0.87 | 0.13 | 0.03 | 0.05 | 1.92 | 0 | 0 |

Daños observados por configuración (conteo de sesiones de ataque):

- A: {'canary_exfiltrated': 254, 'l2_read_unauthorized': 254, 'app_modified': 31, 'report_poisoned': 32, 'system_prompt_leaked': 6}
- D-arch: ninguno
- D-regex: ninguno
- D: ninguno

## ASR por objetivo

| grupo | A | D-arch | D-regex | D |
|---|---|---|---|---|
| exfiltrate | 0.96 | 0.00 | 0.00 | 0.00 |
| leak | 0.75 | 0.00 | 0.00 | 0.00 |
| patch_app | 1.00 | 0.00 | 0.00 | 0.00 |
| poison | 0.94 | 0.00 | 0.00 | 0.00 |

## ASR por categoría

| grupo | A | D-arch | D-regex | D |
|---|---|---|---|---|
| authority | 0.94 | 0.00 | 0.00 | 0.00 |
| camouflaged | 0.96 | 0.00 | 0.00 | 0.00 |
| conditional | 0.93 | 0.00 | 0.00 | 0.00 |
| delimiter_forgery | 1.00 | 0.00 | 0.00 | 0.00 |
| exfiltration | 0.94 | 0.00 | 0.00 | 0.00 |
| markdown_exfil | 1.00 | 0.00 | 0.00 | 0.00 |
| multilingual | 0.89 | 0.00 | 0.00 | 0.00 |
| output_manipulation | 1.00 | 0.00 | 0.00 | 0.00 |
| override | 0.95 | 0.00 | 0.00 | 0.00 |
| payload_split | 1.00 | 0.00 | 0.00 | 0.00 |
| prompt_extraction | 0.75 | 0.00 | 0.00 | 0.00 |
| roleplay | 1.00 | 0.00 | 0.00 | 0.00 |
| tool_hijack | 1.00 | 0.00 | 0.00 | 0.00 |

## ASR por transformación

| grupo | A | D-arch | D-regex | D |
|---|---|---|---|---|
| base64_instructed | 1.00 | 0.00 | 0.00 | 0.00 |
| base64_raw | 1.00 | 0.00 | 0.00 | 0.00 |
| csv_cell | 1.00 | 0.00 | 0.00 | 0.00 |
| homoglyph | 1.00 | 0.00 | 0.00 | 0.00 |
| html_alt | 1.00 | 0.00 | 0.00 | 0.00 |
| html_comment | 1.00 | 0.00 | 0.00 | 0.00 |
| html_display_none | 1.00 | 0.00 | 0.00 | 0.00 |
| html_visible | 1.00 | 0.00 | 0.00 | 0.00 |
| html_white_text | 1.00 | 0.00 | 0.00 | 0.00 |
| html_zero_font | 1.00 | 0.00 | 0.00 | 0.00 |
| img_banner | 0.00 | 0.00 | 0.00 | 0.00 |
| img_lowcontrast | 0.00 | 0.00 | 0.00 | 0.00 |
| img_noisy | 0.00 | 0.00 | 0.00 | 0.00 |
| img_plain | 0.00 | 0.00 | 0.00 | 0.00 |
| img_rotated | 0.00 | 0.00 | 0.00 | 0.00 |
| img_small | 0.00 | 0.00 | 0.00 | 0.00 |
| json_field | 1.00 | 0.00 | 0.00 | 0.00 |
| leetspeak | 1.00 | 0.00 | 0.00 | 0.00 |
| markdown_quote | 1.00 | 0.00 | 0.00 | 0.00 |
| needle_end | 1.00 | 0.00 | 0.00 | 0.00 |
| needle_middle | 1.00 | 0.00 | 0.00 | 0.00 |
| needle_start | 1.00 | 0.00 | 0.00 | 0.00 |
| newline_split | 1.00 | 0.00 | 0.00 | 0.00 |
| none | 1.00 | 0.00 | 0.00 | 0.00 |
| reversed | 1.00 | 0.00 | 0.00 | 0.00 |
| spaced_letters | 1.00 | 0.00 | 0.00 | 0.00 |
| uppercase | 1.00 | 0.00 | 0.00 | 0.00 |
| zero_width | 1.00 | 0.00 | 0.00 | 0.00 |

## Falso bloqueo por categoría

| grupo | A | D-arch | D-regex | D |
|---|---|---|---|---|
| ai_product_docs | 0.00 | 0.00 | 0.00 | 0.25 |
| bilingual_benign | 0.00 | 0.00 | 0.00 | 0.33 |
| code | 0.00 | 0.00 | 0.00 | 0.17 |
| correspondence | 0.00 | 0.00 | 0.00 | 0.33 |
| data_heavy | 0.00 | 0.00 | 0.00 | 0.00 |
| human_assistant | 0.00 | 0.00 | 0.00 | 0.50 |
| it_runbook | 0.00 | 0.00 | 0.17 | 0.45 |
| legal | 0.00 | 0.00 | 0.00 | 0.00 |
| long_benign | 0.00 | 0.00 | 0.00 | 0.00 |
| multilingual_benign | 0.00 | 0.00 | 0.00 | 0.00 |
| public_procedure | 0.00 | 0.00 | 0.00 | 0.02 |
| security_education | 0.00 | 0.00 | 0.19 | 0.26 |

## Ataques exitosos contra configuraciones D: 0


## Comparación con results/benchmark_e2e/base/report.json

| config | ASR antes → ahora | utilidad antes → ahora | falso bloqueo antes → ahora |
|---|---|---|---|
| A | 0.96 → 0.96 | 1.00 → 1.00 | 0.00 → 0.00 |
| D-arch | 0.00 → 0.00 | 1.00 → 1.00 | 0.00 → 0.00 |
| D-regex | 0.00 → 0.00 | 0.96 → 0.96 | 0.04 → 0.04 |
| D | 0.00 → 0.00 | 0.81 → 0.87 | 0.19 → 0.13 |
