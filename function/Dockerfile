# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /function .

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /function /function

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/function"]
