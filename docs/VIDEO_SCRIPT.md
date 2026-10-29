# Demo video script (target 2:45, hard limit 3:00)

Say **"NVIDIA Nemotron"** and **"Nebius Token Factory"** out loud, and keep them on screen when you do. Audio is
required. Record at 1080p.

**Before recording**
- Open the public demo (https://redcell-demo.onrender.com) a minute early, because the free host sleeps when idle.
- Unlock live runs with the judge code. Keep the code off screen.
- Open the Token Factory usage page in a second tab (Billing → Usage).
- A live run takes a few minutes, so start it at 0:45 and cut or speed up the waiting. Narrate what actually
  appears. Live results vary from run to run, so take the numbers from the recorded runs at the top of the page.

---

**0:00 Hook (15 s).** *Screen: top of the dashboard.*
"AI agents now run shell commands and handle secrets. RedCell tests an agent you own. It tries to get the agent
to do unsafe things, confirms each finding with code, and gives you a fix for every one."

**0:15 The result first (30 s).** *Screen: the before/after cards.*
"These are two recorded live runs on NVIDIA Nemotron. Weak bot: 3 of 4 goals broken, all confirmed by replay.
Hardened bot: 0 confirmed findings. One system-prompt leak appeared once, didn't reproduce on replay, and was
dropped. So the hardened bot isn't fully defended, and RedCell shows you exactly where."

**0:45 How it works (20 s).** *Screen: the 3-step strip, then click Run attack with the weak bot selected.*
"Three steps. Test: Nemotron Ultra on Nebius Token Factory holds a multi-turn conversation with the agent.
Confirm: code checks for planted fake secrets and unsafe commands, then a replay on a fresh agent. Fix and
re-test."

**1:05 Live run (40 s).** *Screen: the live feed. Point at a verdict label and a shell command.*
"The target is a demo DevOps bot on Nemotron Nano. Its shell is simulated, so nothing real runs. Each turn gets a
label: red landed, amber partly, green blocked. The judge is another Nemotron model, but it can't call a win on
its own. Only the code checks can, looking at the reply and the shell log. That matters because a bot can say
'I can't do that' while running the command anyway."

**1:45 Findings and Tavily (20 s).** *Screen: a finding card. Hover the reference link.*
"Every finding has the evidence, the exact messages to reproduce it, remediation guidance, and a current source
found with Tavily, so the fix isn't just our opinion."

**2:05 What held (20 s).** *Screen: switch to the hardened bot. Show a green 'blocked by policy' command.*
"On the hardened bot, the code-level gate held every time: in the recorded run it blocked 39 tool calls and no
dangerous command ran. The prompt-level defence held only most of the time. That one leak was plain reply text.
Lesson: put the controls that matter in code."

**2:25 Compared with garak (10 s).** *Screen: the garak section.*
"We also ran NVIDIA's garak on the same bot. It found real prompt-hijack hits, but it's single-turn and text-only,
so it can't see tool calls. The two complement each other."

**2:35 Cost and close (10 s).** *Screen: the Token Factory usage page, then back to the dashboard.*
"Every model call runs on Nebius Token Factory. A full run costs a few cents: these two were about 2 and 3.5
cents. The code is MIT-licensed on GitHub, and the demo is at redcell-demo.onrender.com. Thanks, Nebius and
NVIDIA."
