# Use a specific version of the Rust image for reproducibility
FROM rust:1.89 as builder

# Install necessary build dependencies
# openssl-dev is required for compiling crates that use OpenSSL
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Create a new directory for the application
WORKDIR /app

# Copy the entire project to the working directory
COPY . .

# Build the entire workspace in release mode
# This will compile mproxy, cert_tool, and all other crates
RUN cargo build --release --workspace

# --- Final Stage ---
# Use a slim Debian image for the final container to reduce size
FROM debian:bookworm-slim

# Install runtime dependencies
# - openssl is required by the application
# - ca-certificates is needed to trust TLS certificates
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binaries from the builder stage
COPY --from=builder /app/target/release/mproxy /usr/local/bin/
COPY --from=builder /app/target/release/cert_tool /usr/local/bin/

# Set the working directory for the final image
WORKDIR /app

# Copy the distribution environment file as the default .env file
# This can be overridden using Docker volumes or environment variables
COPY dist.env .env

# Expose standard HTTP and HTTPS ports
EXPOSE 80
EXPOSE 443

# Set the default command to run the mproxy binary
CMD ["/usr/local/bin/mproxy"]
