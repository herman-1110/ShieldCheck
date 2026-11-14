# Use official lightweight Python image
FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Copy application files
COPY index.html server.py /app/
COPY css /app/css
COPY js /app/js

# Cloud Run defaults to port 8080
ENV PORT=8080
EXPOSE 8080

# Run the server
CMD ["python", "server.py"]
