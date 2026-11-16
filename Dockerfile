# No dependencies on purpose: the fetchers and the library are stdlib-only, so this image cannot drift
# by installing something. `probe` is the collector image. `explore` adds the library and serves the
# read-only page over the mounted data directory.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --uid 10001 probe

WORKDIR /app
COPY tools/ tools/

FROM base AS probe

USER probe
ENTRYPOINT ["python", "tools/probe_sources.py"]
CMD ["--data", "/data"]

FROM base AS explore

COPY src/ src/
ENV PYTHONPATH=/app/src
USER probe
EXPOSE 8080
ENTRYPOINT ["python", "tools/explore.py"]
CMD ["--data", "/data", "--bind", "0.0.0.0:8080"]
