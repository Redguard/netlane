# Runs pytest and netlane against the other services of the stack.
# Build context is the repository root.
FROM ghcr.io/astral-sh/uv:python3.15-trixie-slim

# adb and wg for netlane, ssh for netlane and the tests, pkill for the tests.
RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    wireguard-tools \
    openssh-client \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first, so source changes do not reinstall them.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project

COPY config.toml ./
COPY src src
COPY tests tests
RUN uv sync --frozen

COPY --chmod=600 tests/integration/docker/runner/ssh_config /root/.ssh/config

ENV PATH="/src/.venv/bin:$PATH"
CMD ["pytest", "tests/integration", "-rs"]
