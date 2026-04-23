FROM python:3.10-slim

# Install system dependencies, notably nmap
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirement files and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Set default entrypoint to the CLI
ENTRYPOINT ["python", "main.py"]
