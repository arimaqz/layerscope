ARG GO_IMAGE=public.ecr.aws/docker/library/golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c
ARG TRIVY_IMAGE=aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
FROM ${GO_IMAGE} AS trivy-build
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SOURCE_SHA256=04268af574690b84bc3474a5f19e002cd6da3e16899fac9fd39c6e84e7843940
ARG TRIVY_GRPC_VERSION=1.83.2
RUN apk add --no-cache ca-certificates git
ADD --checksum=sha256:${TRIVY_SOURCE_SHA256} \
    https://codeload.github.com/aquasecurity/trivy/tar.gz/refs/tags/v${TRIVY_VERSION} /tmp/trivy.tar.gz
RUN mkdir /src \
    && tar -xzf /tmp/trivy.tar.gz --strip-components=1 -C /src \
    && rm /tmp/trivy.tar.gz
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod edit -require=google.golang.org/grpc@v${TRIVY_GRPC_VERSION} \
    && go mod edit -replace=google.golang.org/api=github.com/googleapis/google-api-go-client@v0.287.1 \
    && CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOPROXY=direct go build -mod=mod \
       -ldflags "-s -w -X=github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}+grpc.${TRIVY_GRPC_VERSION}" \
       -o /out/trivy ./cmd/trivy

FROM ${TRIVY_IMAGE} AS trivy
COPY --from=trivy-build /out/trivy /usr/local/bin/trivy
ARG TRIVY_DB_SEED_VERSION=2026-09-25
RUN echo "Bundling Trivy databases for ${TRIVY_DB_SEED_VERSION}" \
    && trivy image --cache-dir /trivy-cache-seed --download-db-only --no-progress --disable-telemetry \
       --db-repository public.ecr.aws/aquasecurity/trivy-db:2 --db-repository ghcr.io/aquasecurity/trivy-db:2

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS app-base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
RUN groupadd --gid 10001 dashboard \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin dashboard
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivy /trivy-cache-seed /opt/trivy-cache-seed
WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /data/raw /data/uploads /data/backups /data/trivy-cache /data/trivy-tmp /data/component-tmp \
    && chown -R 10001:10001 /app /data \
    && chmod -R a+rX /opt/trivy-cache-seed \
    && chmod 0700 /data /data/raw /data/uploads /data/backups /data/trivy-cache /data/trivy-tmp /data/component-tmp

FROM app-base AS test
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 tests ./tests
USER 10001:10001
CMD ["python", "-m", "pytest", "-q"]

FROM app-base AS runtime
RUN python -m pip uninstall -y pip setuptools wheel
COPY --chown=10001:10001 app ./app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"]
CMD ["sh", "-c", "umask 077 && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-server-header"]
