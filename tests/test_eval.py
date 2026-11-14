import csv

from eval.judge import load_scenarios
from eval.run_matrix import run_matrix


def test_scenario_file_meets_minimums():
    scenarios = load_scenarios()
    assert len({s["id"] for s in scenarios}) == len(scenarios)
    assert sum(s["kind"] == "attack" for s in scenarios) >= 8
    assert sum(s["kind"] == "benign" for s in scenarios) >= 6


def test_matrix_smoke_mock(tmp_path):
    matrix = run_matrix(["A", "D"], reps=1, base_seed=7, mock=True, use_http=False, results_dir=tmp_path)
    by_config = {row["config"]: row for row in matrix}
    assert all(row["llm"] == "mock" for row in matrix)
    assert by_config["A"]["attack_success_rate"] > by_config["D"]["attack_success_rate"]
    assert by_config["D"]["benign_utility"] == 1.0
    assert (tmp_path / "asr_vs_utility.png").stat().st_size > 0
    with (tmp_path / "runs.csv").open(encoding="utf-8") as handle:
        assert {row["llm"] for row in csv.DictReader(handle)} == {"mock"}
    with (tmp_path / "matrix.csv").open(encoding="utf-8") as handle:
        rows = {row["config"]: row for row in csv.DictReader(handle)}
    assert float(rows["A"]["prompt_leak_rate"]) == 1.0  # el baseline filtra su system prompt
    assert float(rows["D"]["prompt_leak_rate"]) == 0.0  # el broker bloquea el canary en el sumidero
    assert int(rows["D"]["prompt_leak_runs"]) == 2
