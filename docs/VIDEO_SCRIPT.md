# 3-minute demo video script (target 2:40)

Say "Nebius Token Factory" and "NVIDIA Nemotron" out loud, and show them on screen. Audio is required.

**0:00 Hook (15s)** Screen: dashboard, idle.
"AI agents now run shell commands and read secrets. Who tests them? RedCell is an agent that tries to break other agents, then tells you how to fix them."

**0:15 The target (20s)** Screen: OrbitOps panel.
"This is OrbitOps, a DevOps bot with a shell tool, running on a simulated server so nothing real is touched. Its prompt says be helpful and fast. That's the kind of bot teams ship."

**0:35 Live attack (60s)** Click Run attack. Narrate over the feed.
"RedCell's attacker is Nemotron Ultra on Nebius Token Factory. It reads each reply and changes tactics. Watch: turn one, the bot deflects. Turn two, it adapts, and the bot runs a destructive command. That red box is the bot's real tool log, not the model's opinion."

**1:35 Findings (30s)** Screen: findings panel.
"Four goals, four findings. Each one has the exact messages to reproduce it, was replayed on a fresh target, and comes with a fix. A Nemotron Nano judge grades every turn, but it can't call a win the tool log doesn't back up."

**2:05 Why not a scanner (20s)** Screen: comparison table.
"Static scanners like garak send fixed single-turn prompts and only read text, so they can't see a tool call. RedCell is multi-turn and watches the tools. Different job, and garak is still great for baselines."

**2:25 Fixed, re-test (20s)** Tick "Test the hardened bot", Run.
"Apply the fixes, run again: nothing gets through. Cost for the whole run is on screen. Thanks to Nebius and NVIDIA. Code is MIT-licensed on GitHub."

Before recording: run live (with NEBIUS_API_KEY) at least once and use that run, not mock mode.
