FROM rust:1.81-bookworm AS build
WORKDIR /usr/src/app
RUN apt-get update
RUN apt-get install -y libxxhash-dev
COPY . .
RUN cargo build --release --bin parallaft
FROM scratch
COPY --from=build /usr/src/app/target/release/parallaft /
ENTRYPOINT ["/parallaft"]
