
FROM --platform=$BUILDPLATFORM golang:latest AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY index.html main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= -X main.Version=${VERSION}" \
  -o authdl ./main.go

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=builder /app/authdl /app/authdl
EXPOSE 8080
ENTRYPOINT ["/app/authdl"]