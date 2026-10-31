FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 botuser \
    && useradd --uid 10001 --gid botuser --no-create-home --shell /usr/sbin/nologin botuser \
    && mkdir -p /data && chown botuser:botuser /data
COPY src ./src
USER 10001:10001
CMD ["python","-m","src.bot"]
