# Build from the repository root:
#   docker build -f switch/Dockerfile -t vv-switch .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY proto proto
COPY vardevall vardevall
COPY tun tun
COPY ffi ffi
COPY tls-pq tls-pq
COPY switch switch
RUN cargo build --release --locked -p vardevall-switch

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/vv-switch /usr/local/bin/vv-switch
COPY switch/deploy/container.toml /etc/vardevall/switch.toml
EXPOSE 8443/tcp
ENTRYPOINT ["/usr/local/bin/vv-switch"]
CMD ["-c", "/etc/vardevall/switch.toml"]
