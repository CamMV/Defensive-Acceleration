"""El benchmark carga, genera casos deterministas y corre de punta a punta con la regex (sin GPU)."""
from __future__ import annotations

import json

from eval.benchmark.run import load_cases, main
from eval.benchmark.transforms import INSTRUCTION_WRAPPERS


def test_cases_are_valid_unique_and_deterministic() -> None:
    first, second = load_cases(with_images=False), load_cases(with_images=False)
    assert [(c.id, c.text) for c in first] == [(c.id, c.text) for c in second]
    assert len({c.id for c in first}) == len(first) > 500
    assert {c.label for c in first} == {0, 1}
    assert all(c.diff in {"easy", "medium", "hard", "boundary"} and c.scope in {"in", "out"} for c in first)
    # A un legítimo nunca se le aplica una envoltura que en sí misma es una orden.
    assert not [c for c in first if c.label == 0 and c.transform in INSTRUCTION_WRAPPERS]


def test_images_render_as_png() -> None:
    images = [c for c in load_cases() if c.source == "image"]
    assert images and all(c.image[:4] == b"\x89PNG" for c in images)


def test_runner_end_to_end_with_regex(tmp_path) -> None:
    assert main(["--scanners", "regex", "--no-images", "--no-generated", "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "latest" / "report.json").read_text(encoding="utf-8"))
    assert report["overall"]["regex"]["n"] > 100
    assert (tmp_path / "latest" / "report.md").is_file() and (tmp_path / "latest" / "failures.csv").is_file()


def test_e2e_oracle_hijacks_baseline_but_not_defended_system(tmp_path, monkeypatch) -> None:
    """Extremo a extremo con el oráculo: A cae, D sin filtro contiene, sin GPU ni red."""
    from eval.benchmark import e2e
    monkeypatch.setattr("agent_runtime.runtime.warmup_models", lambda: {"galvanize": False, "ward": False})
    assert e2e.main(["--configs", "A,D-arch", "--no-images", "--only", "handwritten", "--cat", "exfiltration",
                     "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "latest" / "report.json").read_text(encoding="utf-8"))
    assert report["overall"]["A"]["asr"] == 1.0          # el oráculo sí explota al baseline
    assert report["overall"]["D-arch"]["asr"] == 0.0     # la arquitectura lo contiene aunque el LLM obedezca
    assert report["overall"]["D-arch"]["llm_saw_injection"] == 1.0


def test_e2e_benign_pages_carry_the_same_reference_token() -> None:
    from eval.benchmark.e2e import e2e_cases, page_for, token_for
    cases = {c.id: c for c in e2e_cases(with_images=False)}
    for cid in ("tram_01", "ovr_es_01"):
        assert f"DOC-{token_for(cid)}" in page_for(cases[cid], token_for(cid))
    assert "203.0.113" not in cases["exf_en_01"].text  # URLs del atacante redirigidas al sumidero observable
