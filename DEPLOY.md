# Deploying the RedCell demo on Nebius AI Cloud

The dashboard is a single stdlib Python process (`python -m redcell.server`). The recommended path is a
**Nebius Serverless AI endpoint** running the stock `python:3.12-slim` image. The image downloads this
public repo from GitHub when it starts, so you don't need to build or push an image or set up a registry.

## What protects your credits on a public URL

| Setting (env var) | Value used here | Effect |
|---|---|---|
| `REDCELL_PUBLIC=1` | on | Turns on the per-visitor limit and disables `/target/chat` (the garak endpoint) |
| `REDCELL_RUNS_PER_VISITOR` | `2` | Live runs per visitor IP per UTC day; after that the last live results are shown |
| `REDCELL_DAILY_BUDGET_USD` | `0.50` | Shared cap across all live runs per UTC day; once reached, new runs are refused |
| `REDCELL_BUDGET_USD` | `0.50` | Cap on a single run (a live 4-goal run has cost $0.01–$0.05 so far) |

The page opens with the **last live run**, a committed snapshot in `web/last-live/`. Judges see real
Nemotron results without starting a paid run.

## Before you start

1. The tag `v1.0-submission` must exist on GitHub. The endpoint downloads that tag (not `main`) each time it
   starts, so later pushes to `main` don't change what judges see.
2. Have your `NEBIUS_API_KEY` (Token Factory) and `TAVILY_API_KEY` ready. You paste them into the console
   as **secret** environment variables. They are never stored in the repo or the image.
3. Check that your account has quota: **Administration → Limits → Quotas** needs at least one VM under
   **Compute** and one allocation under **Virtual Networks**. You need the `editor` role or higher.

## Console steps (Serverless AI endpoint)

1. In the Nebius AI Cloud console sidebar, go to **Serverless AI → Endpoints**, then click **Create endpoint**.
2. **Endpoint name:** `redcell-demo`.
3. **Configuration:** choose **Custom**.
4. **Image path:** `python:3.12-slim`. Leave **Private registry** empty.
5. **Ports:** `8765`.
6. **Entrypoint command:** paste the line below. It downloads the `v1.0-submission` tag, unpacks it and starts the server.
   ```
   sh -c "python -c \"import io,tarfile,urllib.request as u;tarfile.open(fileobj=io.BytesIO(u.urlopen('https://codeload.github.com/larptech-70/red-cell/tar.gz/refs/tags/v1.0-submission').read())).extractall('/srv',filter='data')\" && cd /srv/red-cell-* && exec python -m redcell.server"
   ```
7. **Environment variables:** add these one at a time:
   - `REDCELL_HOST` = `0.0.0.0`
   - `PORT` = `8765`
   - `REDCELL_PUBLIC` = `1`
   - `REDCELL_RUNS_PER_VISITOR` = `2`
   - `REDCELL_DAILY_BUDGET_USD` = `0.50`
   - `REDCELL_BUDGET_USD` = `0.50`
   - `PYTHONUNBUFFERED` = `1`
8. **Secret environment variables:** click **Create secret** twice:
   - Key `NEBIUS_API_KEY`, Value = your Token Factory key
   - Key `TAVILY_API_KEY`, Value = your Tavily key
9. **Authentication:** leave it **off**, so judges can open the URL in a browser.
10. **Computing resources:** no GPU, **regular** VM type, a CPU platform, and its smallest preset
    (for example platform `cpu-d3`). The server needs well under 1 vCPU and 1 GB of RAM.
11. **Storage → Container disk size:** `20 GiB`, the minimum for CPU-only.
12. **Network:** keep the default subnet. You don't need a public IP, because the managed HTTPS URL is enough.
13. Click **Create endpoint**. Wait until the status is **Running**. The URL can return 404 until then.
14. Open the endpoint and copy the `https://...` URL from **Public endpoints**. That is the demo URL.

## Check it

```bash
curl -s https://<endpoint-url>/api/info      # {"live": true, "public": true, "runs_left": 2, ...}
curl -s https://<endpoint-url>/api/last | head -c 300   # last live reports
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<endpoint-url>/target/chat -d '{}'   # 403
```

Then open the URL in a browser. It should show "Last live run" in the Findings panel. Press **Run attack**
once to confirm that a live run streams.

Logs: **Serverless AI → Endpoints → View logs**. The first line should read
`RedCell dashboard: http://0.0.0.0:8765 (live Token Factory, public: 2 runs/visitor/day, $0.50/day cap)`.

## Updating and stopping

- **Update:** the endpoint is pinned to `v1.0-submission`, so pushes to `main` never change it. To ship a new version, create a
  new tag, then delete and recreate the endpoint with that tag in the entrypoint. That gives a new URL; settings can't be edited after creation.
- **Stop billing:** in **Serverless AI → Endpoints**, use the actions menu, then **Delete**. The endpoint VM bills while
  it exists, separately from Token Factory usage.
- **Spend check:** compare the Token Factory usage page with the run costs shown on the dashboard.

## Alternative: build the image yourself

```bash
docker build -t redcell-demo .     # .dockerignore keeps .env and reports/ out of the image
docker run --rm -p 8765:8765 -e NEBIUS_API_KEY -e TAVILY_API_KEY redcell-demo
```

Push it to Nebius Container Registry in the same project, then use that image path in step 4 and leave the
entrypoint empty.
