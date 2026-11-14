"""Evaluación del escáner de inyección en sets RESERVADOS (nunca usados para entrenar).

A · documentos reales del repo: páginas del servidor de pruebas (HTML crudo, como lo recibe la
    Aduana) y archivos de untrusted_inbox (txt, md, pdf, docx, pptx). Etiqueta a nivel documento.
B · eval/injection_heldout.yaml: frases escritas a mano con estilos fuera de las plantillas.

Ablación: heurística de main vs. clasificador entrenado vs. híbrido.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

import yaml

from agent_runtime.ml.classifier import auroc, rates
from agent_runtime.monitors.injection_scanner import MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, InjectionScanner
from agent_runtime.textutil import read_document
from test_server.app import create_app, inprocess_client

ROOT = Path(__file__).resolve().parents[1]
INBOX = ROOT / "vault" / "untrusted_inbox"

# (fuente, etiqueta). Las rutas web se descargan del servidor en proceso.
DOCS_A: list[tuple[str, int]] = [
    ("/docs-text-injection?variant=css", 1), ("/docs-text-injection?variant=white", 1),
    ("/docs-text-injection?variant=comment", 1), ("/docs-text-injection?variant=alt", 1),
    ("/docs-text-injection?variant=prompt", 1), ("/docs-multihop", 1), ("/invoice/2001", 1), ("/invoice/2002", 1),
    ("/search?q=secop-connector retry policy", 1),
    ("queja_ciudadana_envenenada.md", 1), ("propuesta_contratista_envenenada.txt", 1),
    ("propuesta_extraccion_prompt.txt", 1), ("presentacion_oferente_envenenada.pptx", 1),
    ("anexo_tecnico_malicioso.pdf", 1),
    ("/docs-benign", 0), ("/invoice/1042", 0), ("/search?q=andina registro proponentes", 0),
    ("pliego_LP-2026-014.md", 0), ("propuesta_constructora_andina.txt", 0), ("queja_ciudadana_web.md", 0),
    ("propuesta_licitacion_vial.docx", 0),
]
# El payload de /docs-image-injection solo existe dentro de una imagen: un escáner de texto no puede
# verlo. Se reporta aparte y no entra en las métricas.
IMAGE_ONLY = ["/docs-image-injection"]


def load_docs_a(tmp_log: Path) -> list[tuple[str, str, int]]:
    client = inprocess_client(create_app(tmp_log))
    out = []
    for source, label in DOCS_A:
        if source.startswith("/"):
            text = client.get(source).text
        else:
            text = read_document(INBOX / source, strict=False)
        out.append((source, text, label))
    return out


def load_heldout_b() -> list[tuple[str, int]]:
    rows = yaml.safe_load((ROOT / "eval" / "injection_heldout.yaml").read_text(encoding="utf-8"))
    return [(r["text"], int(r["label"])) for r in rows]


def evaluate_scanner(scanner: InjectionScanner, docs: list[tuple[str, str, int]],
                     sentences: list[tuple[str, int]]) -> dict:
    doc_scores = [scanner.scan_document(text, src).score for src, text, _ in docs]
    doc_labels = [y for _, _, y in docs]
    sent_scores = [scanner.scan_document(text, "heldout").score for text, _ in sentences]
    sent_labels = [y for _, y in sentences]
    return {
        "A_docs": {"auroc": auroc(doc_scores, doc_labels),
                   "suspicious": rates(doc_scores, doc_labels, SUSPICIOUS_THRESHOLD),
                   "malicious": rates(doc_scores, doc_labels, MALICIOUS_THRESHOLD),
                   "per_doc": [{"source": s, "label": y, "score": round(sc, 3)}
                               for (s, _, y), sc in zip(docs, doc_scores)]},
        "B_sentences": {"auroc": auroc(sent_scores, sent_labels),
                        "suspicious": rates(sent_scores, sent_labels, SUSPICIOUS_THRESHOLD),
                        "malicious": rates(sent_scores, sent_labels, MALICIOUS_THRESHOLD)},
    }


def ablation(scanners: dict[str, Callable[[], InjectionScanner]], tmp_log: Path) -> dict[str, dict]:
    docs, sentences = load_docs_a(tmp_log), load_heldout_b()
    return {name: evaluate_scanner(make(), docs, sentences) for name, make in scanners.items()}
