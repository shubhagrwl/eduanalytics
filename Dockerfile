# Use the official Golang 1.23 image as the base image
FROM golang:1.23

LABEL maintainer="Shubham Agarwal<sshubham.aal@gmail.com>"
# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules and download the dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the project files into the container
COPY . .

# Build the Go application
RUN go build -o main .

# Copy environment configuration
COPY .env .

# Expose the application port
EXPOSE 9090

# Start the application
CMD ["./main"]