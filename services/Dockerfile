# Один Dockerfile для всех пяти сервисов: нужный сервис выбирается аргументом SERVICE
# Если Docker Hub недоступен: BASE_IMAGE=mirror.gcr.io/library/python:3.12-slim
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}
ARG SERVICE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SERVICE_NAME=${SERVICE}
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /var/log/audit && chown 10001:10001 /var/log/audit
COPY common/ ./common/
COPY ${SERVICE}/main.py ./main.py
USER 10001
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
