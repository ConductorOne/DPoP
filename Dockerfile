# Base image
FROM golang:1.23-alpine AS builder
RUN apk add make
WORKDIR /lambda
COPY . /lambda
RUN make build GOOS=linux GOARCH=arm64

# Final image
FROM alpine:latest
RUN apk add ca-certificates
WORKDIR /
COPY --from=builder /lambda/build/arm64_linux/main /
RUN chmod 777 /main

CMD ["/main"]