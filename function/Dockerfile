FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY function /function

ENV FUNCTION_TARGET=TokenHandler

EXPOSE 8080

# The :nonroot base already runs as UID 65532 (its own image config sets
# User=65532; /etc/passwd has nonroot:x:65532:65532), so this changes nothing
# at runtime. Stated explicitly because Trivy's AVD-DS-0002 fires on the
# absence of a USER instruction, regardless of the base image default.
USER 65532:65532

ENTRYPOINT ["/function"]
