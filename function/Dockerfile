FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY function /function

ENV FUNCTION_TARGET=TokenHandler

EXPOSE 8080

# The :nonroot base already runs as UID 65532 (its own image config sets
# User=65532; /etc/passwd has nonroot:x:65532:65532), so this changes nothing
# at runtime. Stated explicitly so the runtime user is visible in the
# Dockerfile itself, regardless of the base image default.
USER 65532:65532

ENTRYPOINT ["/function"]
