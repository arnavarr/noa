# Minimal OCI image of the `noa` binary, e.g. for an in-cluster dialer:
#   noa proxy-multi /identity/identity.json <service>:<port>...
# ONLY the static (musl) binary: no shell, no packages and no system CA store; `noa` trusts only the
# controller CA carried by the enrolled identity.
#
# Build (the binary is compiled outside, so the image needs no toolchain and no network):
#   cargo build --release --locked --target x86_64-unknown-linux-musl --bin noa
#   cp target/x86_64-unknown-linux-musl/release/noa deploy/noa/noa
#   docker build -t noa:dev deploy/noa
FROM scratch
COPY noa /noa
# Unprivileged user (nobody); `scratch` has no /etc/passwd, the numeric uid is enough.
USER 65534:65534
ENTRYPOINT ["/noa"]
