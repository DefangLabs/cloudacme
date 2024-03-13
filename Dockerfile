# syntax=docker/dockerfile:1.4
ARG GOVERSION=1.22

FROM --platform=${BUILDPLATFORM} golang:${GOVERSION} AS build

# These two are automatically set by docker buildx
ARG TARGETARCH
ARG TARGETOS

# prebuild the standard library (including runtime) to be cached
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install std

WORKDIR /src
COPY --link go.mod go.sum ./
RUN go mod download

ARG GOSRC=.
COPY --link ${GOSRC} ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-w -s" -o /server "${BUILD}"

FROM alpine as certs
RUN apk update && apk add ca-certificates

FROM busybox:musl
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --link --from=build /server /server
ENTRYPOINT [ "/server" ]
