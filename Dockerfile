FROM python:3.11-slim

# Install system dependencies (Nmap)
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port (Render uses $PORT)
EXPOSE 8000

# Start the application using uvicorn
CMD ["sh", "-c", "uvicorn webapp:app --host 0.0.0.0 --port ${PORT:-8000}"]
