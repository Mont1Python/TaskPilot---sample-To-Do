#!/bin/bash

# START LOCAL DOCKER APPLICATION
# Simple one-command startup for local development

echo "=========================================="
echo "Starting To-Do App with Docker Compose"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker ps > /dev/null 2>&1; then
    echo "ERROR: Docker is not running!"
    echo "Please start Docker Desktop first."
    exit 1
fi

echo "Starting containers..."
docker-compose up -d

echo ""
echo "Waiting for app to be ready..."
sleep 5

# Check if containers are running
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "=========================================="
    echo "✓ Application is RUNNING!"
    echo "=========================================="
    echo ""
    echo "Access your app at:"
    echo "  http://localhost:3001"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
    echo ""
    echo "To stop the app:"
    echo "  run: stop-docker.sh"
    echo ""
else
    echo ""
    echo "ERROR: Container failed to start"
    echo "Check logs with: docker-compose logs"
    exit 1
fi
