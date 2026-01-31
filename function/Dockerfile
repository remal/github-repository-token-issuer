FROM gcr.io/distroless/static-debian12:nonroot@sha256:cba10d7abd3e203428e86f5b2d7fd5eb7d8987c387864ae4996cf97191b33764

COPY function /function

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/function"]
