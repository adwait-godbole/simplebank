# Build stage
FROM golang:1.23.2-alpine3.20 AS builder
WORKDIR /app
COPY . .
RUN go build -o main main.go
RUN apk add curl
RUN curl -L https://github.com/golang-migrate/migrate/releases/download/v4.18.1/migrate.linux-amd64.tar.gz | tar xvz

# Run stage
FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/migrate ./migrate
COPY app.env .
COPY start.sh .
COPY wait-for.sh .
COPY db/migration ./migration

# Make sure scripts are executable
RUN chmod +x /app/start.sh
RUN chmod +x /app/wait-for.sh

EXPOSE 8080

# Both of the below "WILL" not required "IF" our docker-compose file is overwriting them.
CMD [ "/app/main" ]
ENTRYPOINT [ "/app/start.sh" ]
