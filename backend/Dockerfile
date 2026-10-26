FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

RUN useradd --uid 10001 --user-group --create-home --shell /usr/sbin/nologin escudo

COPY --chown=escudo:escudo server.py model.py model.json ./

USER 10001

EXPOSE 8080

CMD ["python", "server.py"]
