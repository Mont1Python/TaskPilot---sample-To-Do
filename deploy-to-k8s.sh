#!/bin/bash

# To-Do App Kubernetes Deployment Script
# Deploys the To-Do app to Kubernetes cluster

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}To-Do App Kubernetes Deployment${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}kubectl is not installed${NC}"
    exit 1
fi

# Check cluster connectivity
echo -e "${BLUE}Checking cluster connectivity...${NC}"
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}Cannot connect to Kubernetes cluster${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Connected to cluster${NC}\n"

# Build Docker image
echo -e "${BLUE}Building Docker image...${NC}"
if docker build -t todo-app:latest .; then
    echo -e "${GREEN}✓ Docker image built successfully${NC}\n"
else
    echo -e "${RED}✗ Failed to build Docker image${NC}"
    exit 1
fi

# Load image to cluster (for local clusters like kind/minikube)
echo -e "${BLUE}Loading image to cluster...${NC}"
if kind load docker-image todo-app:latest 2>/dev/null || minikube image load todo-app:latest 2>/dev/null; then
    echo -e "${GREEN}✓ Image loaded to cluster${NC}\n"
else
    echo -e "${YELLOW}⚠ Could not load image to local cluster (OK for remote clusters)${NC}\n"
fi

# Apply Kubernetes manifests
echo -e "${BLUE}Applying Kubernetes manifests...${NC}"
if kubectl apply -f k8s-todo-deployment.yaml; then
    echo -e "${GREEN}✓ Kubernetes manifests applied${NC}\n"
else
    echo -e "${RED}✗ Failed to apply manifests${NC}"
    exit 1
fi

# Wait for deployments to be ready
echo -e "${BLUE}Waiting for deployments to be ready...${NC}"
kubectl rollout status deployment/todo-backend -n todo-app --timeout=5m

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Get service information
echo -e "${BLUE}Service Information:${NC}"
kubectl get svc -n todo-app

echo ""
echo -e "${BLUE}Access your To-Do App:${NC}"
TODO_IP=$(kubectl get svc todo-backend-service -n todo-app -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
if [ ! -z "$TODO_IP" ]; then
    echo -e "  ${GREEN}http://$TODO_IP${NC}"
else
    echo -e "  ${YELLOW}LoadBalancer IP pending (may take a moment)${NC}"
    echo -e "  Use: ${GREEN}kubectl get svc -n todo-app${NC}"
fi

echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  View pods:              kubectl get pods -n todo-app -o wide"
echo "  View logs:              kubectl logs -f deployment/todo-backend -n todo-app"
echo "  View events:            kubectl get events -n todo-app"
echo "  Scale deployment:       kubectl scale deployment todo-backend -n todo-app --replicas=3"
echo "  Delete deployment:      kubectl delete namespace todo-app"
echo ""
