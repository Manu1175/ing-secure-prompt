# SecurePrompt — One-page Demo Outline

## Presentation titles (from kickoff deck, condensed)
1) **Project & Objectives** — What SecurePrompt is and why it matters for banking LLM usage.
2) **Milestones** — Milestone 1 (Fri 03 Oct 2025): MVP demo & metrics. Milestone 2 (Fri 10 Oct 2025): pass/fail scrubbing.
3) **Architecture & Flow** — detectors → scrub → policy (C2/C3/C4) → audit (hash chain) → de-scrub (role + justification).
4) **MVP Ladder** — MVP-0..3: prompts → files (pdf/png OCR) → adaptive policies & de-scrub → API & metrics.
5) **Demo Script** — live scrub of prompt/pdf/png; flip C-level; view audit; selective de-scrub.
6) **Performance & Metrics** — precision/recall on golden set; throughput; OCR latency (budget).
7) **Risks & Mitigations** — OCR quality, false positives, performance, audit integrity.
8) **Deliverables & Next Steps** — code, tests, manifests, metrics, dashboard (wk2), hardening.

---

## Slide content (fill with screenshots/metrics)
- **Top banner:** SecurePrompt logo/title + date.
- **Left column:** Objectives, milestones, MVP ladder.
- **Right column:** Architecture diagram; demo flow bullets.
- **Footer widgets:** Precision/recall numbers, entity mix bar, de-scrub count.
