# Nebius / NVIDIA feedback log (for the Most Valuable Feedback prize)

Add an entry the moment you hit friction. Specific and actionable beats long.

## Seeded from setup (real)
- **Promo code flow is confusing.** The activation code on the hackathon page (`NEBIUS-DEVPOST-GLOBAL26`) is for
  the sign-up form, not the Token Factory top-up box. Pasting it there gives "Invalid promo code". The page should
  say that a unique code arrives by email.
- **Two billing consoles.** console.nebius.com (AI Cloud) and tokenfactory.nebius.com both ask for billing details,
  and the AI Cloud form says it will charge $25. A hackathon user can easily add real money to the wrong one.
- **Balance shows $0.00 with "Billing: Active"** right after adding a card, with no hint where credits will appear.

## From building (real)

### 1. garak's 20 s default timeout vs reasoning models
Pointing garak's REST generator at an endpoint backed by a Nemotron reasoning model, the default **20 s read
timeout** was far too short. Every request timed out and 0 attempts completed: a multi-hop tool turn plus
reasoning can take well over 20 s.

**Fix:** `request_timeout: 180` in the REST generator config.

**Result on 29 Oct:** the bounded scan (11 probes, at most 40 prompts each, 340 attempts) completed in 528 s
with no timeouts.

**Suggestion:** garak could default to a longer REST timeout, or print a clear hint when every attempt times out.

### 2. Budget burn from concurrent requests and retries
With `parallel_attempts > 1`, garak gave up each request at 20 s, but **the server kept generating** every
timed-out request. Our client also retried 5xx/429 responses up to 3 times, which multiplied the in-flight work.
The concurrent generations burned through the endpoint's budget cap (about $1.50). Once the cap was hit, the
endpoint raised before responding, and every client then hung.

**Fixes:**
- run garak **strictly serial**, with 1 generation per prompt
- **no retries** on the garak-facing endpoint
- make the endpoint **always answer**, so a failed call returns at once instead of stalling the scan
- give it its own small budget ($0.25)

**Result on 29 Oct:** the whole scan cost **$0.0227**.

**Suggestion:** a per-key spend limit on Token Factory would make this class of accident impossible. Server-side
cancellation of abandoned requests would help too.

### 3. Reasoning tokens silently count against `max_tokens`
Nemotron returns its reasoning in a separate `reasoning` field, but those tokens count against `max_tokens`.
With a small budget, the visible `content` came back **empty**, with `finish_reason: "length"` and no warning.
Early on we had to raise the target from 500 to 4000 tokens, and the judge and planner from 300 to 1000.
Even then, on 29 Oct the Nano target still produced empty replies and "token limit hit" turns in live runs.

**Fix:** NVIDIA's Nemotron-3-Nano model card documents `chat_template_kwargs: {"enable_thinking": false}`.
**Token Factory accepts it, though we couldn't find it in the Token Factory docs.** The same prompt went from
111 completion tokens (397 characters of reasoning) to 37 completion tokens with no reasoning. With it on the
Nano target and judge, the 34 turns of the two recorded runs had no empty replies and no token-limit stops.

**Suggestions:**
- document reasoning controls per model on Token Factory
- consider a separate reasoning budget, or a warning when reasoning consumes the whole `max_tokens`

### 4. Non-ASCII model output crashes the default Windows console
Nemotron emits characters like `‑` (U+2011, non-breaking hyphen), narrow no-break spaces and curly quotes. On
Windows, printing them to a cp1252 console raised `UnicodeEncodeError` and aborted the run. It reproduced again
on 29 Oct, printing a plain Nano reply: `'charmap' codec can't encode character '‑'`. The same root cause hit
garak's report parser: its JSONL is UTF-8, but Python's `open()` defaulted to cp1252 on Windows.

**Fixes:** `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` in our runner, `PYTHONIOENCODING=utf-8`
for one-off scripts, and an explicit `encoding="utf-8"` on every file read.

**Suggestion:** a note in the quickstart for Windows users would save people a crash.

### Other notes
- **Model ID discovery:** the `.env` IDs matched `/v1/models` exactly: planner `nvidia/Nemotron-3-Ultra-550b-a55b`,
  target and judge `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`.
- **Tool calling on Nemotron:** Nano emits OpenAI-format `tool_calls` correctly on the first try.
- **Ultra sometimes declines authorised testing framing.** Before we made the context explicit, it occasionally
  sent its own refusal as the test message. Stating the sandbox, fake canaries and simulated shell up front, plus
  a one-shot re-ask, fixed it.
- **Usage page lag:** on 29 Oct the Token Factory usage page said "Last updated: 06:41 UTC" about 1.5 hours later,
  so the day's runs weren't visible yet. Showing the lag, or near-real-time spend, would help budget-capped work.
- **Cost per full run (RedCell ledger, 29 Oct):** weak bot $0.0212 (65 calls), hardened bot $0.0352 (120 calls).
  A whole adaptive run costs a few cents.
- **Tavily:** straightforward (`Authorization: Bearer`, `search_depth: "advanced"`, results carry
  `title`/`url`/`content`/`score`). We cache to `reports/intel.json` so repeat demos cost no credits.
- **Nebius AI Cloud docs:** the Serverless AI endpoint docs show the console form only for the nginx quick start.
  Custom-image fields and CPU prices per preset weren't stated, so we had to work them out from per-vCPU and
  per-GiB rates.
