FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f

COPY function /function

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/function"]
