# Microsoft Defender MCP Server Dockerfile
# Multi-stage build for smaller final image

# Stage 1: Build stage
FROM python:3.11-slim as builder

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install the package
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Runtime stage
FROM python:3.11-slim as runtime

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash mcpuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Create certs directory for Azure certificate-based auth
RUN mkdir -p /certs && chown mcpuser:mcpuser /certs

# Switch to non-root user
USER mcpuser

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check - verify the module can be imported
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import mcp_defender" || exit 1

# Default command - run the MCP server
ENTRYPOINT ["python", "-m", "mcp_defender.server"]

# Labels for container metadata
LABEL org.opencontainers.image.title="Microsoft Defender MCP Server" \
      org.opencontainers.image.description="MCP Server for Microsoft Defender Advanced Hunting - execute KQL queries via natural language" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="Lord Abbett" \
      org.opencontainers.image.source="https://github.com/trickyfalcon/mcp-defender"
