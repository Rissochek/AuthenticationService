FROM golang:alpine AS builder

WORKDIR /app

COPY AuthService/go.mod .

COPY Proto/ /Proto/

RUN go mod download

COPY AuthService/. .

RUN go build -o main ./cmd/server

FROM alpine

WORKDIR /app

RUN apk add --no-cache tzdata

COPY --from=builder /app/main .

COPY AuthService/.env .

EXPOSE ${AUTH_HOST_PORT}

CMD ["./main"]
