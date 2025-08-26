# syntax=docker/dockerfile:1

# Build the application from source
FROM docker.io/golang:1.25.0 AS build-stage

WORKDIR /app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /usr/local/bin/nestor github.com/simonhege/nestor


# Run the tests in the container
FROM build-stage AS run-test-stage
RUN CGO_ENABLED=0 go test -v ./...

# Deploy the application binary into a lean image
FROM gcr.io/distroless/static-debian12 AS build-release-stage
WORKDIR /

COPY --from=build-stage /usr/local/bin/nestor /nestor

USER nonroot:nonroot

ENTRYPOINT ["/nestor"]
