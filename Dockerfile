FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="HeaderGuard" \
      org.opencontainers.image.description="Analizador educativo de cabeceras HTTP de seguridad" \
      org.opencontainers.image.version="1.3.0" \
      org.opencontainers.image.authors="abyssnx" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY app ./app
RUN pip install --no-cache-dir .

USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
