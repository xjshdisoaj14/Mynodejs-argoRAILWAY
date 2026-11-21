# 关键改动：cloudflared 和 xray 在「构建阶段」装好，
# 不在「运行阶段」联网下载。这是原仓库部署失败的主要原因。
FROM node:20-alpine

ARG TARGETARCH

RUN apk add --no-cache curl ca-certificates unzip bash tzdata

# ---- cloudflared ----
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      arm64) CFD="cloudflared-linux-arm64" ;; \
      *)     CFD="cloudflared-linux-amd64" ;; \
    esac; \
    curl -fsSL --retry 3 --retry-delay 2 -o /usr/local/bin/cloudflared \
      "https://github.com/cloudflare/cloudflared/releases/latest/download/${CFD}"; \
    chmod +x /usr/local/bin/cloudflared; \
    /usr/local/bin/cloudflared --version

# ---- xray ----
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      arm64) XR="Xray-linux-arm64-v8a.zip" ;; \
      *)     XR="Xray-linux-64.zip" ;; \
    esac; \
    curl -fsSL --retry 3 --retry-delay 2 -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/latest/download/${XR}"; \
    unzip -o /tmp/xray.zip -d /usr/local/bin/; \
    chmod +x /usr/local/bin/xray; \
    rm -f /tmp/xray.zip; \
    /usr/local/bin/xray version

WORKDIR /app
COPY package.json ./
COPY index.js ./

ENV NODE_ENV=production
ENV PORT=8000
EXPOSE 8000

CMD ["node", "index.js"]
