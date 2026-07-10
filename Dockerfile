# ---- build ----
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /lampa-agent .

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /lampa-agent /usr/local/bin/lampa-agent

# /downloads — куда качать (мапьте на том NAS)
# /config    — хранит ключ агента и код спаривания (мапьте, чтобы код не менялся)
VOLUME ["/downloads", "/config"]
EXPOSE 47801

# Панель доступна на http://<ip-nas>:47801
# Задайте свой токен через переменную UI_TOKEN (Basic Auth, логин любой).
ENV UI_TOKEN=""
ENTRYPOINT ["sh", "-c", "exec lampa-agent -headless -ui 0.0.0.0:47801 -dir /downloads -config /config/agent.json ${UI_TOKEN:+-ui-token \"$UI_TOKEN\"}"]
