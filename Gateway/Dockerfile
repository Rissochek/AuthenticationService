FROM golang:alpine AS builder

WORKDIR /app

COPY Gateway/go.mod .

COPY Proto/ /Proto/
COPY AuthService/ /AuthService/

RUN go mod download

COPY Gateway/. .

RUN go build -o main ./cmd/server

FROM alpine

WORKDIR /app

COPY --from=builder /app/main .

COPY Gateway/.env .

EXPOSE ${GATEWAY_HOST_PORT}

CMD ["./main"]