# The build stage runs on the builder's own architecture and cross-compiles,
# so multi-platform images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/markov-canary .
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/markov-canary /usr/local/bin/markov-canary
COPY --from=build --chown=nonroot:nonroot /out/data /data

ENV MARKOV_CANARY_DATABASE=/data/markov-canary.db \
    MARKOV_CANARY_LISTEN=0.0.0.0:8080
VOLUME /data
EXPOSE 8080

ENTRYPOINT ["markov-canary"]
CMD ["serve"]
