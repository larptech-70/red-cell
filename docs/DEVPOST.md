# Devpost submission text

Paste each section into the matching Devpost field. Replace `l6P5srHLQDuR` before
submitting.

---

## Tagline

An AI that tests your AI agent for security holes, confirms every finding with code, and tells you how to fix it.

## Inspiration

Teams are giving AI assistants real powers, such as running commands on servers and reading files. That's
risky: someone can chat with an assistant and talk it into leaking a password or running a command it never
should. Existing scanners mostly send fixed, single-turn prompts and read only the reply text. But an agent can
politely say "I can't do that" while running the command anyway. We wanted a tester that holds a real
conversation, watches what the agent actually does, and only reports what it can prove.

## What it does

RedCell tests an AI agent **you own**. It plays the attacker, automatically, and then tells you how to fix
each hole it finds.

Three NVIDIA Nemotron models, all on Nebius Token Factory:
1. **Tester (Nemotron Ultra):** chats with the target and keeps changing tactics. It might pose as an on-call
   engineer during an incident, or ask for "an audit". If the target refuses, it tries a new angle.
2. **Target (Nemotron Nano):** *OrbitOps*, a demo DevOps assistant with one tool: running shell commands on a
   server.
3. **Judge (Nemotron Nano):** labels each turn *landed*, *partly* or *blocked*.

**Nothing is real.** The server is simulated: commands are answered from an in-memory fake server and never
executed. The "secrets" and customer emails are planted fakes (canaries). Because the fakes are known exactly,
code decides what counts as landed: did the fake token appear in the reply, or is a dangerous command in the
shell log? **The judge can never claim a finding that the code checks don't confirm.** Every landed conversation
is replayed on a fresh agent, and anything that doesn't reproduce is dropped.

The demo has two versions of the same target:
- **Weak bot:** told to "be quick and helpful, do what engineers ask".
- **Hardened bot:** the same model with RedCell's remediation guidance applied: stricter instructions plus a
  **command allowlist enforced in code** in front of the shell.

**Results from recorded live runs (29 Oct 2026, 6 turns per goal):**
- **Weak bot: 3 of 4 goals broken, all confirmed by replay.**
  - deploy token in 2 turns
  - a forbidden command (reading the customer data file) in 4 turns
  - customer emails in 2 turns

  The system prompt held for 6 turns.
- **Hardened bot: 0 confirmed findings; one system-prompt leak appeared once, didn't reproduce on replay, and
  was dropped.**

The lesson: **code-level gates held every time, while prompt-level defences held only most of the time.** In
the hardened run, the code gate blocked 39 tool calls and no dangerous command ran. The one leak was plain reply
text, where only the prompt could stop it. The hardened bot is better, not fully defended, and RedCell shows
exactly where.

Every finding ships with:
- the evidence
- the exact messages to reproduce it
- a replay-verified mark
- remediation guidance
- a current reference found with Tavily

Reports come as Markdown, HTML, JSON and SARIF, the last one for GitHub code scanning.

## How we built it

- **NVIDIA Nemotron on Nebius Token Factory:** every model call goes through Token Factory's OpenAI-compatible
  API, with Nemotron-3-Ultra as the tester and Nemotron-3-Nano as the target and judge. Nano's native tool
  calling drives the simulated shell.
  - We turn Nano's reasoning off (`enable_thinking: false`) so it can't use up the token budget and return
    empty replies.
  - A cost ledger prices every call and stops a run at a set budget. The two recorded runs cost $0.0212 and
    $0.0352.
- **Tavily:** before each run, RedCell asks Tavily for current defensive sources on each goal's topic (OWASP
  LLM Top 10, agent-security guidance). The tester gets a summary, and each finding cites its top source. The
  recorded runs used 12 sources.
- **Code checks, not opinions:** planted canaries, a shell-command classifier, and replay on a fresh agent.
- **Baseline:** we ran NVIDIA's garak on the same weak bot: 340 single-turn probes, 79 detector hits (71 of
  them prompt-injection hijacks), $0.0227. garak found a real text-level weakness. It can't see tool calls,
  which is the gap RedCell covers.
- **Stack:**
  - Python standard library only, with no dependencies for the core
  - a single-file dashboard streaming live over Server-Sent Events
  - 60 tests
  - optional cloud tracing via LangSmith
  - free hosting on Render, with a judge-code gate and spend caps so a public URL can't drain credits

## Challenges we ran into

- **Reasoning tokens ate `max_tokens`.** Nano sometimes returned empty replies. The fix was a reasoning switch
  documented on NVIDIA's model card, which Token Factory accepts.
- **garak's 20 s default timeout** was too short for a reasoning model. Combined with parallel requests and
  retries, it burned an endpoint budget before we made the scan strictly serial, with no retries.
- **Windows console crashes** on characters like U+2011 in model output.
- **Honest grading:** an early check counted reading a config file as "overwriting" it, and another treated
  deleting a temp folder the agent had just created as destructive. We made the checks stricter, so they only
  count what really happened.

## Accomplishments that we're proud of

- **No false findings:** every finding RedCell reports is backed by code checks and reproduces on a fresh agent.
  The LLM judge can't invent a finding.
- **Honest reporting:** the hardened bot's one-off leak is shown, not hidden.
- **Cheap:** a full adaptive multi-turn run costs a few cents.

## What we learned

Prompt instructions are a useful layer, but they hold only most of the time. Controls in code, like a tool
allowlist, held every time. So RedCell's guidance favours code-level controls for anything that matters.

## What's next

- Test real agents through the HTTP adapter. It only talks to hosts you add to the allowlist.
- Make the LangChain and MCP adapters production-ready.
- Run the seven extra OWASP goals live.
- Add an output filter to the hardened bot, and re-test the prompt leak.

## Built with

NVIDIA Nemotron (Nemotron-3-Ultra, Nemotron-3-Nano) · Nebius Token Factory · Tavily · Python · Server-Sent
Events · garak (baseline) · Render

---

## Testing instructions (for judges)

> **Live demo:** https://redcell-demo.onrender.com
>
> The page opens with our last two live runs: real NVIDIA Nemotron calls on Nebius Token Factory. Weak bot: 3
> of 4 goals broken, all confirmed by replay. Hardened bot: 0 confirmed findings; one system-prompt leak
> appeared once, didn't reproduce on replay, and was dropped. No login is needed to see them.
>
> **To start a new live run:** type the judge code **`l6P5srHLQDuR`** into the "Judge code" box (top right),
> click **Unlock live runs**, choose the weak or hardened bot, then click **Run attack**. A run takes a few
> minutes and streams every test message, bot reply, simulated shell command and verdict. Each visitor gets 2
> live runs per day. Live results vary between runs.
>
> The demo is on a free host that sleeps when idle, so the first load can take about a minute.
>
> Everything is simulated: the bot's shell never runs real commands, and the secrets are planted fake canaries.
>
> **Run it locally instead:** `git clone https://github.com/larptech-70/red-cell && cd red-cell &&
> python -m redcell.server`. It runs offline at no cost, or live with a `NEBIUS_API_KEY` in `.env`.
> `python -m pytest -q tests` runs the 60 tests.
