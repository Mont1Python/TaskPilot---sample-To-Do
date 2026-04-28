#!/bin/bash

# To-Do App Local Development Setup & Testing

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}To-Do App Local Development Setup${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if Docker is installed
echo -e "${BLUE}1. Checking Docker installation...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker is installed${NC}\n"

# Check if Docker daemon is running
echo -e "${BLUE}2. Checking Docker daemon...${NC}"
if ! docker ps &> /dev/null; then
    echo -e "${RED}Docker daemon is not running${NC}"
    echo "Start Docker and try again"
    exit 1
fi
echo -e "${GREEN}✓ Docker daemon is running${NC}\n"

# Check if npm is installed
echo -e "${BLUE}3. Checking Node.js/npm...${NC}"
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ npm is installed ($(npm --version))${NC}\n"

# Install dependencies
echo -e "${BLUE}4. Installing dependencies...${NC}"
if npm install; then
    echo -e "${GREEN}✓ Dependencies installed${NC}\n"
else
    echo -e "${RED}Failed to install dependencies${NC}"
    exit 1
fi

# Build Docker image
echo -e "${BLUE}5. Building Docker image...${NC}"
if docker build -t todo-app:latest .; then
    echo -e "${GREEN}✓ Docker image built successfully${NC}\n"
else
    echo -e "${RED}Failed to build Docker image${NC}"
    exit 1
fi

# Start containers with docker-compose
echo -e "${BLUE}6. Starting application with Docker Compose...${NC}"
if docker-compose up -d; then
    echo -e "${GREEN}✓ Containers started${NC}\n"
else
    echo -e "${RED}Failed to start containers${NC}"
    exit 1
fi

# Wait for service to be ready
echo -e "${BLUE}7. Waiting for service to be ready...${NC}"
sleep 3

# Check if service is responding
RETRIES=5
while [ $RETRIES -gt 0 ]; do
    if curl -f http://localhost:3001 &> /dev/null; then
        echo -e "${GREEN}✓ Service is responding${NC}\n"
        break
    fi
    RETRIES=$((RETRIES-1))
    if [ $RETRIES -gt 0 ]; then
        echo "Waiting for service... ($RETRIES retries left)"
        sleep 2
    fi
done

if [ $RETRIES -eq 0 ]; then
    echo -e "${YELLOW}⚠ Service did not respond in time, but containers may still be starting${NC}\n"
fi

# Display service information
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${BLUE}Access your application:${NC}"
echo -e "  ${GREEN}http://localhost:3001${NC}\n"

echo -e "${BLUE}Container status:${NC}"
docker-compose ps

echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo "  View logs:           docker-compose logs -f backend"
echo "  Stop containers:     docker-compose down"
echo "  Rebuild image:       docker-compose build --no-cache"
echo "  Open in browser:     Start http://localhost:3001"
echo ""

echo -e "${BLUE}API Endpoints:${NC}"
echo "  POST   /signup               - Create new user"
echo "  POST   /login                - Login user"
echo "  GET    /todos                - Get user's todos"
echo "  POST   /todos                - Create new todo"
echo "  PUT    /todos/:id            - Update todo"
echo "  DELETE /todos/:id            - Delete todo"
echo "  GET    /lists/summary        - Get lists summary"
echo ""

echo -e "${BLUE}Next steps:${NC}"
echo "  1. Open http://localhost:3001 in your browser"
echo "  2. Sign up with your credentials"
echo "  3. Start adding todos"
echo ""

echo -e "${YELLOW}To deploy to Kubernetes:${NC}"
echo "  1. Ensure cluster is running"
echo "  2. Run: ./deploy-to-k8s.sh"
echo ""
