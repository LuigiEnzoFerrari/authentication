FROM golang:1.25.3-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth .

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache postgresql-client

COPY --from=builder /app/auth .

EXPOSE 8080

CMD ["./auth"]
