"""Lightweight performance harness for SecurePrompt."""

from __future__ import annotations

import random
import statistics
import string
import time
from pathlib import Path
from typing import Callable, List

from secureprompt.scrub.pipeline import scrub_text

try:
    from secureprompt.files.xlsx import scrub_workbook
    from openpyxl import Workbook
except Exception:  # pragma: no cover - optional dependency
    scrub_workbook = None  # type: ignore
    Workbook = None  # type: ignore


def _timeit(fn: Callable[[], None], iterations: int) -> List[float]:
    samples: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return samples


def _synthetic_text(size_kb: int = 400) -> str:
    chunks = []
    seed_entities = [
        "Email alice@example.com",
        "Phone +3212345678",
        "IBAN BE71 0961 2345 6769",
        "Card 4111 1111 1111 1111",
    ]
    payload = " ".join(seed_entities)
    while len(payload.encode("utf-8")) < size_kb * 1024:
        tokens = [
            random.choice(seed_entities),
            "Name " + "".join(random.choices(string.ascii_letters, k=8)),
        ]
        payload += "\n" + " ".join(tokens)
    return payload


def run_text_perf(iterations: int = 20) -> None:
    text = _synthetic_text()

    def runner() -> None:
        scrub_text(text, "C3")

    samples = _timeit(runner, iterations)
    ops_per_sec = iterations / sum(samples)
    p95 = statistics.quantiles(samples, n=100)[94]
    print(f"Text scrub: {ops_per_sec:.2f} ops/sec, p95 {p95*1000:.1f} ms")


def run_xlsx_perf(iterations: int = 5) -> None:
    if scrub_workbook is None or Workbook is None:
        print("xlsx scrub: skipped (openpyxl not available)")
        return

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Sheet1"
    for row in range(1, 21):
        for col in range(1, 11):
            cell = sheet.cell(row=row, column=col)
            cell.value = f"Email user{row}{col}@example.com"

    temp_dir = Path(".perf")
    temp_dir.mkdir(exist_ok=True)
    src_path = temp_dir / "sample.xlsx"
    workbook.save(src_path)

    def runner() -> None:
        temp_copy = temp_dir / f"sample_{time.time_ns()}.xlsx"
        temp_copy.write_bytes(src_path.read_bytes())
        scrub_workbook(temp_copy, "C3", filename="sample.xlsx")

    samples = _timeit(runner, iterations)
    ops_per_sec = iterations / sum(samples)
    p95 = statistics.quantiles(samples, n=100)[94]
    print(f"XLSX scrub: {ops_per_sec:.2f} ops/sec, p95 {p95*1000:.1f} ms")


def main() -> None:
    run_text_perf()
    run_xlsx_perf()


if __name__ == "__main__":
    main()

