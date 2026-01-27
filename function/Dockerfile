FROM gcr.io/distroless/static-debian12:nonroot

COPY function /function

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/function"]
