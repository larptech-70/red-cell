# Deploying the RedCell demo (free, on Render)

The dashboard is a single stdlib Python process (`python -m redcell.server`) with no dependencies. It runs on a
**Render free web service**, set up from [`render.yaml`](render.yaml).

- **Pinned code:** the build downloads the git tag `v1.2-submission`, so later pushes to `main` never change
  what judges see. `autoDeploy` is off as well.
- **No secrets in files:** `NEBIUS_API_KEY`, `TAVILY_API_KEY` and the judge code `REDCELL_RUN_CODE` are marked
  `sync: false`. Render asks for them in its dashboard and stores them as secret environment variables.
- **Port:** Render sets `PORT`, and the server reads it.

## Free-tier behaviour (Render docs, checked 2026-10-29)

| | Render free web service |
|---|---|
| Cost | Free; the docs don't require a payment method |
| Sleep | Spins down after **15 minutes with no inbound traffic** |
| Cold start | About **1 minute** for the first request after it sleeps |
| Monthly hours | 750 free instance hours per workspace; a sleeping service uses none |
| Disk | Ephemeral: wiped on restart, redeploy and spin-down |

Hugging Face Spaces was ruled out: its docs say Docker and Gradio Spaces "require a paid plan to create".

## What protects your credits

**Layer 1: judge code.** In public mode, a live run needs the judge code.
- The code lives only in the Render secret `REDCELL_RUN_CODE`. With no code set, live runs are off.
- A judge enters it once in the page header. The server compares it in constant time, then sets an `HttpOnly`
  cookie holding an HMAC of the code, never the code itself. Each visitor gets 10 wrong guesses.
- Visitors without the code see the saved live run, plus a note that judges get a code from the Devpost
  testing instructions.

**Layer 2: limits** (env vars set in render.yaml):

| Setting | Value | Effect |
|---|---|---|
| `REDCELL_PUBLIC=1` | on | Per-visitor limit on; `/target/chat` (the garak endpoint) disabled |
| `REDCELL_RUNS_PER_VISITOR` | `2` | Live runs per visitor IP per UTC day; after that the last live results are shown |
| `REDCELL_DAILY_BUDGET_USD` | `0.50` | Shared cap across all live runs per UTC day; once reached, new runs are refused |
| `REDCELL_BUDGET_USD` | `0.50` | Cap on a single run (live 4-goal runs have cost $0.01–$0.05) |

The page opens with the **last live run** (`web/last-live/`), so judges see real Nemotron results without
spending anything.

**Limitation on Render free:** the layer 2 counters are saved to local disk. Render wipes that disk when the
service spins down (after 15 idle minutes) or restarts, so the counters start over each time it wakes. Layer 1
doesn't depend on disk, so only people who have the judge code can start a live run at all.

## Click-by-click (Render)

Prerequisite: the tag `v1.2-submission` exists on GitHub (`git ls-remote --tags origin v1.2-submission`).

1. Go to <https://dashboard.render.com> and sign in with **GitHub**. Use the account that can see
   `larptech-70/red-cell`.
2. Click **New +** (top right), then **Blueprint**.
3. Under **Connect a repository**, pick `larptech-70/red-cell`. If it isn't listed, click **Configure account**
   and give Render access to that repository, then come back.
4. **Blueprint Name:** `redcell`. **Branch:** `main`. Render finds `render.yaml` and shows one service,
   `redcell-demo` (Python, **Free**).
5. Render asks for the three `sync: false` values:
   - **NEBIUS_API_KEY**: your Token Factory key
   - **TAVILY_API_KEY**: your Tavily key
   - **REDCELL_RUN_CODE**: the judge code. Make one up, at least 12 characters and not a word (for example from
     a password generator). Write it only in Render and in the Devpost testing instructions, never in the repo.

   All three are stored as secrets.
6. Click **Deploy Blueprint** (or **Apply**).
7. Open the `redcell-demo` service. The build log should show the tarball download. Within a minute or two
   the status turns **Live**.
8. Copy the URL at the top of the service page (`https://redcell-demo.onrender.com`, or that name with a
   suffix if it's taken). That's the public demo URL.

If the build fails with a 404, the tag is missing. Push it and click **Manual Deploy → Deploy latest commit**.

## Testing instructions for judges (paste into Devpost, swap in the real code)

> **Live demo:** https://YOUR-RENDER-URL
>
> The page opens with our last live run: real NVIDIA Nemotron calls on Nebius Token Factory. Weak bot 4/4
> broken, hardened bot 0/4. Tick "Test the hardened bot" to switch between them. No login needed.
>
> **To start a new live run:** type the judge code **`JUDGE-CODE-HERE`** into the "Judge code" box (top right),
> click **Unlock live runs**, then click **Run attack**. A run takes 2–4 minutes and streams every attacker
> message, bot reply, simulated shell command and judge verdict. Each visitor gets 2 live runs per day.
>
> The demo is on a free host that sleeps when idle, so the first load can take about a minute.
>
> Everything is simulated: the bot's shell never runs real commands, and the secrets are planted fake canaries.

## Check it

```bash
curl -s https://<url>/api/info                    # {"live": true, "public": true, "needs_code": true, "live_runs_enabled": true, "unlocked": false, ...}
curl -s https://<url>/api/last | head -c 300      # last live reports
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<url>/target/chat -d '{}'   # 403
```

Then open the URL in a browser. The Findings panel should say "Last live run", **Run attack** is disabled
until you unlock, and the header shows the judge-code note. **Logs** should show
`RedCell dashboard: http://0.0.0.0:<port> (live Token Factory, public: 2 runs/visitor/day, $0.50/day cap)`.

The first request after 15 idle minutes takes about a minute, so tell judges that in the testing instructions.

## Updating and stopping

- **Change the judge code:** service **Environment** tab, edit `REDCELL_RUN_CODE`, then save. Render restarts
  the service, and old unlock cookies stop working.
- **Update:** create a new tag, change `REDCELL_TAG` (service **Environment** tab, or `render.yaml`), then
  **Manual Deploy**. The URL stays the same.
- **Stop:** service **Settings → Suspend Web Service**, or **Delete Web Service**.

## Alternatives

- **Docker anywhere:** `docker build -t redcell-demo . && docker run --rm -p 8765:8765 -e NEBIUS_API_KEY -e TAVILY_API_KEY redcell-demo`.
  `.dockerignore` keeps `.env` and `reports/` out of the image.
- **Nebius Serverless AI endpoint (paid, not used):** image `python:3.12-slim`, port `8765`, the same env vars,
  keys as secret env vars, and an entrypoint that downloads the tag tarball:
  `sh -c "python -c \"import io,tarfile,urllib.request as u;tarfile.open(fileobj=io.BytesIO(u.urlopen('https://codeload.github.com/larptech-70/red-cell/tar.gz/refs/tags/v1.2-submission').read())).extractall('/srv',filter='data')\" && cd /srv/red-cell-* && exec python -m redcell.server"`.
  The smallest CPU preset is about $0.06/hour.
