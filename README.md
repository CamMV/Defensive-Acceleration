# Defensive-Acceleration — Frente 01 "Agent Security"

Prototipo defensivo medible contra *indirect prompt injection* para un Asistente de
Auditoría / Due Diligence. Hackathon Defensive Acceleration (AI Safety Colombia × IEEE CS Uniandes).

README inicial; se completa al cierre de la Fase 5.

## Reparto por sub-equipo

| Módulo | Responsable |
|---|---|
| `agent_runtime/contracts.py` | Compartido (cambios con acuerdo de ambos) |
| `agent_runtime/broker.py`, `monitors/egress.py`, `tools/`, `test_server/`, `baselines/` | Ciberseguridad |
| `agent_runtime/enclaves/customs.py`, `monitors/intent_drift.py`, `quarantine.py` (procedencia) | ML |
| `agent_runtime/enclaves/orchestrator.py`, `vault_worker.py`, `eval/` | Compartido |
