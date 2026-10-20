# The production image: one static binary, no shell, no package manager, a non-root user.
FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" -o /out/airlance-auth ./cmd/airlance-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/airlance-auth /airlance-auth
USER nonroot:nonroot
ENTRYPOINT ["/airlance-auth"]
CMD ["serve"]
