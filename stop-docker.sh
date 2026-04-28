#!/bin/bash

# STOP LOCAL DOCKER APPLICATION
# Simple one-command shutdown

echo "=========================================="
echo "Stopping To-Do App"
echo "=========================================="
echo ""

# Check if containers are running
if docker-compose ps | grep -q "Up"; then
    echo "Stopping containers..."
    docker-compose down
    echo ""
    echo "=========================================="
    echo "✓ Application STOPPED"
    echo "=========================================="
    echo ""
    echo "To start again:"
    echo "  run: start-docker.sh"
    echo ""
else
    echo "No containers are running"
    exit 0
fi
