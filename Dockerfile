# No dependencies on purpose: the fetchers are stdlib-only, so this image is small, auditable, and cannot drift.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --uid 10001 probe

WORKDIR /app
COPY tools/ tools/

USER probe
ENTRYPOINT ["python", "tools/probe_sources.py"]
CMD ["--data", "/data"]
