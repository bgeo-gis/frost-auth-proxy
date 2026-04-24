FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY cmd ./cmd

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/frost-auth-proxy ./cmd/frost-auth-proxy


FROM gcr.io/distroless/static-debian12:nonroot

ENV PORT=9090
EXPOSE 9090

COPY --from=build /out/frost-auth-proxy /frost-auth-proxy

USER nonroot:nonroot

ENTRYPOINT ["/frost-auth-proxy"]
