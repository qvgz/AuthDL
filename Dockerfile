FROM golang:latest AS builder
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum index.html main.go ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o authdl ./main.go

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=builder /app/authdl /app/authdl
EXPOSE 8080
ENTRYPOINT ["/app/authdl"]