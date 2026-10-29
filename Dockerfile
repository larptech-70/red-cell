# RedCell public demo. Stdlib only, so the image is just Python + the source.
# Keys are NOT baked in: pass NEBIUS_API_KEY / TAVILY_API_KEY as (secret) environment variables.
FROM python:3.12-slim
WORKDIR /app
COPY redcell ./redcell
COPY web ./web
COPY scripts ./scripts
ENV REDCELL_HOST=0.0.0.0 \
    PORT=8765 \
    REDCELL_PUBLIC=1 \
    REDCELL_RUNS_PER_VISITOR=2 \
    REDCELL_DAILY_BUDGET_USD=0.50 \
    REDCELL_BUDGET_USD=0.50 \
    PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python", "-m", "redcell.server"]
