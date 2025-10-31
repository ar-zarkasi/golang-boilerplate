ARG PLATFORM=linux/amd64
FROM --platform=$PLATFORM golang:1.25.3-bookworm AS builder

RUN apt update && apt upgrade -y
# Environment setup
ENV GOPATH /go
ENV PATH $GOPATH/bin:$PATH
ARG TZ=Asia/Jakarta
ENV TZ=${TZ}

# Set local timezone
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

RUN go install github.com/swaggo/swag/cmd/swag@latest

# Create app directory
RUN mkdir -p /go/src/app
WORKDIR /go/src/app

# Copy source code
COPY . .

# Go module tidy and build
RUN go mod tidy
RUN go swag init
RUN go build -o /go/dist/app .

# Final stage
FROM --platform=$PLATFORM debian:bookworm AS base

RUN apt update && apt upgrade -y

# Set local timezone
ARG TZ=Asia/Jakarta
ENV TZ=${TZ}
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /var/www
COPY --from=builder /go/dist/app .
COPY config ./config

ARG PORT=5000
ENV PORT=${PORT}

# Ensure binary is executable
RUN chmod +x ./app

EXPOSE $PORT

CMD ["./app"]