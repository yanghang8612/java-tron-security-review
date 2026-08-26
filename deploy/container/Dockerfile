FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03

ARG CODEX_SECURITY_VERSION=0.1.16

RUN apt-get -o Acquire::http::No-Cache=true update \
    && apt-get -o Acquire::http::No-Cache=true install \
      --yes --no-install-recommends \
        ca-certificates \
        git \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --system --uid 10001 --group --home /home/scanner scanner

COPY deploy/container/package.json deploy/container/package-lock.json /opt/codex-security/

# The final codex invocation loads the architecture-specific native package. Keeping that check in
# the build prevents an image with only the JavaScript launcher from passing validation.
RUN --mount=type=cache,id=jtsr-npm-node24-v1,target=/root/.npm,sharing=locked \
    npm ci \
      --prefix /opt/codex-security \
      --include=optional \
      --ignore-scripts \
      --no-audit \
      --no-fund \
    && test "$(node -p 'require("/opt/codex-security/node_modules/@openai/codex-security/package.json").version')" \
      = "$CODEX_SECURITY_VERSION" \
    && ln -s \
      /opt/codex-security/node_modules/.bin/codex-security \
      /usr/local/bin/codex-security \
    && codex-security --version \
    && /opt/codex-security/node_modules/.bin/codex --version

COPY src /opt/jtsr/src
COPY config /opt/jtsr/config
COPY knowledge /opt/jtsr/knowledge
COPY prompts /opt/jtsr/prompts
COPY --chmod=0755 deploy/container/jtsr /usr/local/bin/jtsr

ENV PATH="/opt/codex-security/node_modules/.bin:${PATH}" \
    PYTHONPATH="/opt/jtsr/src" \
    PYTHONUNBUFFERED=1

RUN jtsr --version

# The single-server runtime mounts the root-owned, immutable target at this exact path and runs
# the scanner as uid 10001. Trust only that fixed mount point for Git ownership checks.
RUN git config --system --add safe.directory /scan/target

WORKDIR /opt/jtsr

# CodeBuild replaces ENTRYPOINT for custom images. Keeping the image default harmless also makes
# local smoke tests straightforward.
CMD ["jtsr", "--help"]
