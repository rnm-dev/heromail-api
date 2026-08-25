FROM golang:1.25-alpine

WORKDIR /app

# Pinned: air >= v1.62 requires Go 1.26+, newer than this base image.
RUN go install github.com/air-verse/air@v1.61.7

COPY go.mod go.sum ./
RUN go mod download

COPY . .

EXPOSE 8080
CMD ["air", "-c", ".air.toml"]
