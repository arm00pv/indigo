FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY mfa_sdk/ ./mfa_sdk/
COPY backend/ ./backend/

# Create logs directory
RUN mkdir -p /app/logs && touch /app/logs/app.log

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=backend.app

# Expose port
EXPOSE 5000

# Run with Gunicorn (Initialize DB first)
CMD ["sh", "-c", "flask init-db && gunicorn -w 1 -b 0.0.0.0:5000 --access-logfile - backend.app:app"]
