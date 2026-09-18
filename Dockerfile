FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TFIR_DATA_DIR=/data
WORKDIR /app
COPY requirements.lock pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip install --no-cache-dir --no-deps . \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin tracefoundry \
    && mkdir /data && chown tracefoundry:tracefoundry /data
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
ENTRYPOINT ["tracefoundry"]
CMD ["serve", "--host", "0.0.0.0"]
