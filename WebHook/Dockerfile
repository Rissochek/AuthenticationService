FROM golang:alpine AS builder

WORKDIR /app

COPY WebHook/go.mod .

COPY AuthService/ /AuthService/

RUN go mod download

COPY WebHook/. .

RUN go build -o main ./cmd/server

FROM alpine

WORKDIR /app

COPY --from=builder /app/main .

COPY WebHook/.env .

EXPOSE ${WEBHOOK_PORT}

CMD ["./main"]