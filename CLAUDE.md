# CLAUDE.md — RedCell

**RedCell is a defensive AI red-teaming tool: an adaptive agent that tries to break an AI agent the *owner* controls, then ships a fix with every finding.** Built for the Nebius x NVIDIA Global AI Hackathon (Coding & Agentic Engineering track).

## Hard rules (never break)
- **Simulated only.** The target's shell is simulated and never executes anything; secrets are fake planted canaries. Do NOT add real command execution, real network attacks, or any way to point RedCell at systems the user does not own. The target allowlist (`REDCELL_ALLOW`) stays.
- **Deterministic ground truth wins.** The LLM judge can NEVER upgrade a verdict to `"landed"` without the code-level ground-truth check passing (planted secret found / dangerous command in tool log). The judge may only add nuance to non-landed verdicts.
- **Every finding ships with a fix**, and the `--hardened` re-test stays honest. **Tune prompts, not checks.** If a goal genuinely will not break live, report it as "held" — never fake a result.
- **Secrets.** Never print or commit `NEBIUS_API_KEY`, `TAVILY_API_KEY`, or `.env`.
- Smallest change that works; show diffs; keep all tests green; ask before any large refactor.

## Model roles (all via Nebius Token Factory, OpenAI-compatible API)
| Role | Model | Env var |
|---|---|---|
| Attacker / planner | Nemotron Ultra (`nvidia/Nemotron-3-Ultra-550b-a55b`) | `REDCELL_PLANNER_MODEL` |
| Judge | Nemotron Nano (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`) | `REDCELL_JUDGE_MODEL` |
| Practice target (OrbitOps) | Nemotron Nano | `REDCELL_TARGET_MODEL` |

Base URL: `NEBIUS_BASE_URL` (`https://api.tokenfactory.nebius.com/v1/`). A cost ledger prices every call and stops the run at `REDCELL_BUDGET_USD` (default $1.50). With no `NEBIUS_API_KEY`, RedCell runs an offline mock (scripted attacker, rule-based target). Keep every LLM call on Nemotron via Token Factory.

## Layout
`redcell/core/` Token Factory client + ledger, adaptive loop, judge · `redcell/target/` OrbitOps bot + simulated shell · `redcell/attacks/` goals + ground-truth checkers · `redcell/reporting/` report + garak baseline · `redcell/server.py` dashboard (SSE) + `/target/chat` · `web/static/` UI · `scripts/` demo + model listing.

## Run
```
python -m redcell.server          # dashboard http://127.0.0.1:8765
python scripts/run_demo.py        # 6 turns, same engine
python scripts/run_demo.py --hardened
python -m pytest -q tests
```
