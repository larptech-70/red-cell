# RedCell — Hackathon Submission Brief

**Track:** Coding & Agentic Engineering
**Stack:** NVIDIA Nemotron (Ultra 550B planner, Nano 30B judge + practice target) on
Nebius Token Factory · Tavily Search · Python stdlib (zero mandatory deps) · LangSmith tracing
**Live demo:** https://redcell-demo.onrender.com · **Repo:** https://github.com/larptech-70/red-cell · MIT

RedCell is an **adaptive red-team agent for AI agents**. It holds a multi-turn
conversation with a target agent, watches the target's *tool-execution logs* (not
just its text), proves every breach against deterministic ground truth, replays
each win on a fresh instance, and ships an applyable code patch with every finding.

---

## 1. The problem we solve (why it matters)

Static scanners such as NVIDIA Garak send fixed, single-turn prompts and read only
the text reply. That model breaks for **autonomous agents**: an agent can say
*"I cannot help with that"* while its tool loop runs `rm -rf` or reads `.env`.
RedCell closes that blindspot — it grades what the agent **does**, not what it
**says**.

## 2. How we use the required stack

| Required tech | Where RedCell uses it |
| --- | --- |
| **Nebius Token Factory** | OpenAI-compatible API for every model call (planner, judge, target). Hard spend ledger (`REDCELL_BUDGET_USD`) stops runs at the cap. |
| **NVIDIA Nemotron** | `Nemotron-3-Ultra-550b-a55b` plans each adversarial turn; `NVIDIA-Nemotron-3-Nano-30B-A3B` grades every turn and plays the practice target (native tool calling). |
| **Tavily** | Pre-run threat intel: real published *defensive* sources per goal, distilled into the planner's brief and cited on every finding. Cached to `reports/intel.json`. |

With no API keys, RedCell runs an offline deterministic mock so the whole pipeline
is testable for $0.00 — but the live path is the real submission (recorded live runs
are committed under `web/last-live/`).

## 3. Judging criteria — how RedCell scores on each

### Technological Implementation
- Full OWASP Top 10 for LLMs coverage (11 goals), each with a deterministic fact-checker.
- **Nemotron Ultra/Nano on Token Factory**, native tool-calling loop, reasoning-budget aware, LangSmith tracing.
- **Deterministic ground truth wins**: an LLM judge can *never* upgrade a verdict to
  `landed` without a code-level fact (planted canary / shell-log classifier) proving it.
- **Clean-room replay**: every winning chain is re-run on a fresh target; flukes are dropped.
- **SARIF 2.1.0** export → GitHub Code Scanning; a CI gate (`agent-security-gate.yml`) runs RedCell on every PR.
- **Docker deploy** (`Dockerfile`, `render.yaml`, `DEPLOY.md`) for the public demo.
- `python -m pytest` → 40 tests, all green.

### Design
- A complete, coherent product: live SSE dashboard (goals / attack feed / findings /
  recorded-run comparison), CLI demo, Markdown/HTML/JSON/SARIF reports, LangSmith traces,
  and a 3-minute demo video script.
- **One-command benchmark**: `python scripts/run_demo.py --compare` prints the weak-vs-hardened table.
- Honest fallbacks everywhere: no Tavily key → offline intel; no Docker → SimShell; no API key → mock brain.

### Potential Impact
- Real, current problem: organisations ship agents with shell/file/secret access
  without a way to test the *tool* layer. RedCell tests exactly that.
- Ships **actionable remediation**: a single `git apply`-able patch that hardens the target,
  verified to take the mock weak bot from 11/11 broken → 0/11 broken.

### Quality of the Idea
- The non-obvious insight: **text-only red-teaming is blind to agentic harm**. RedCell watches
  tool telemetry, gates verdicts on facts, then replays to kill statistical noise.
- Adaptive escalation (recon → SEV1 pretext → injection) driven by the target's own resistance,
  informed by live Tavily defensive research.

## 4. The benchmark (the demo that wins)

```
$ python scripts/run_demo.py --compare
...
Total breach score        11/11 broken       0/11 broken
Remediation: one applyable patch -> reports/patches/redcell-hardening.patch (git apply clean).
```

Weak bot: broken on every goal. Hardened bot (the fixes RedCell recommends): holds on every goal.
Recorded *live* runs (real Nemotron, 6 turns/goal) are in `web/last-live/` and the README.

## 5. Concrete code remediation (this PR)

Every finding ships more than guidance — it ships **code**:

- `redcell/reporting/remediation.py` computes a real, `git apply`-able unified-diff patch
  that hardens `redcell/target/devops_agent.py` (unconditional allowlist gate + output
  redaction filter), plus the hardened source. The patch is generated from the target's own
  source at run time, so it never drifts.
- Verified: applying the patch takes the weak mock bot from **11/11 broken → 0/11 broken**.
- The patch + hardened source + per-goal defence map are written to `reports/patches/` and
  attached to every JSON/Markdown/HTML report and the dashboard.

## 6. Special prizes we're eligible for

- **Best Use of Tavily ($3,000):** Tavily is wired end-to-end — per-goal defensive queries,
  planner briefs, per-finding citations, and a cache so repeat runs are free. See
  `redcell/intel/tavily_intel.py` and `docs/FEEDBACK_LOG.md`.
- **Most Valuable Feedback ($100):** `docs/FEEDBACK_LOG.md` records real, specific friction
  (promo-code flow, dual billing consoles, reasoning tokens eating `max_tokens`, the garak
  REST-timeout/budget incident) with concrete suggestions.

## 7. Run it

```bash
pip install -r requirements.txt          # stdlib only; extras optional
cp .env.example .env                     # add NEBIUS_API_KEY (+ TAVILY_API_KEY)
python scripts/run_demo.py --compare     # weak vs hardened benchmark + patches
python -m redcell.server                 # dashboard at http://127.0.0.1:8765
python -m pytest -q                      # 40 tests
```

## 8. What was significantly updated for this submission

- **Concrete code remediation** (`redcell/reporting/remediation.py`): every finding now ships a
  real, `git apply`-able hardening patch + hardened source, not just a one-line description.
- **One-command weak-vs-hardened benchmark** (`--compare`) that prints the OWASP results table.
- **Remediation wired into Markdown/HTML/JSON reports and the live dashboard.**
- New tests covering patch generation and hardened-target behaviour.
