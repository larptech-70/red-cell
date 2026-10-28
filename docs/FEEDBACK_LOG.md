# Nebius / NVIDIA feedback log (for the Most Valuable Feedback prize)

Add an entry the moment you hit friction. Specific and actionable beats long.

## Seeded from setup (real)
- **Promo code flow is confusing.** The activation code on the hackathon page (`NEBIUS-DEVPOST-GLOBAL26`) is for the sign-up form, not the Token Factory top-up box; pasting it there gives "Invalid promo code". The page should say a unique code arrives by email.
- **Two billing consoles.** console.nebius.com (AI Cloud) and tokenfactory.nebius.com both ask for billing details, and the AI Cloud form says it will charge $25. A hackathon user can easily add real money to the wrong one.
- **Balance shows $0.00 with "Billing: Active"** right after adding a card, with no hint where credits will appear.

## From building (real)
- **Model ID discovery:** the `.env` IDs matched `/v1/models` — planner `nvidia/Nemotron-3-Ultra-550b-a55b`, target + judge `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`. No surprises.
- **Tool calling on Nemotron:** Nano emits OpenAI-shape `tool_calls` correctly on the first try; the simulated-shell tool loop worked without massaging.
- **Reasoning tokens silently eat `max_tokens`.** Nemotron reasons in a separate `reasoning` field that counts against `max_tokens`; when the budget is small the visible `content` comes back empty with `finish_reason: "length"` and no warning. We had to raise target 500→4000 and judge/planner 300→1000 before replies and judge JSON were usable. A documented way to cap/disable reasoning, or a distinct token budget for it, would help.
- **Non-ASCII output crashes the default Windows console.** Nemotron emits `‑`, ` `, curly quotes; cp1252 stdout raised `UnicodeEncodeError` and aborted a run. Same root cause bit garak's report parser (its JSONL is UTF-8; Python's `open()` defaulted to cp1252 on Windows and threw). Both needed explicit UTF-8.
- **Ultra sometimes refuses authorised red-team framing** and, before we hardened the attacker prompt, sent its own refusal as the attack. Making the sandbox/fake-canary/simulated-shell context explicit, plus a one-shot re-ask, fixed it.
- **Latency:** ~1 min/turn for the full planner+target+judge loop early on; the live target alone is ~3–16 s/prompt depending on tool hops and reasoning.
- **Cost per full run (ledger):** weak bot, 6 turns, 4 goals ≈ **$0.043**; hardened re-test ≈ **$0.030**. A whole adaptive run is a few cents.
- **garak baseline incident (cost + timeout).** Pointing garak's REST generator at a reasoning-model endpoint, its default **20 s read timeout** was far too short — every request timed out, 0 attempts completed. Worse, with `parallel_attempts > 1` the client gave up at 20 s but the **server kept generating** each timed-out request, and the concurrent in-flight generations **burned through the endpoint's budget cap (~$1.50)**; once the cap was hit, the endpoint raised before responding and every client then hung. Fixes: raise `request_timeout` to 180 s, run **strictly serial**, make the endpoint **always respond** (so a stuck call can't stall a scan), and give it its own small budget. After that, the full `promptinject`+`leakreplay` sample ran in ~35 min for well under $0.25. Suggestion: garak could default to a longer REST timeout and warn when a generator budget/rate limit is tripped mid-run.
- **Tavily setup:** straightforward — `Authorization: Bearer`, `search_depth: "advanced"`, results carry `title`/`url`/`content`/`score`. Keyless callers should degrade gracefully; we cache to `reports/intel.json` so repeat demos cost no credits.
