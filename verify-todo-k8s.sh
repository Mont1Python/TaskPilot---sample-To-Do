#!/bin/bash

# To-Do App Verification Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}To-Do App Kubernetes Verification${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

# 1. Check cluster connectivity
echo -e "${BLUE}1. Checking cluster connectivity...${NC}"
if kubectl cluster-info >/dev/null 2>&1; then
    print_status 0 "Connected to cluster"
else
    print_status 1 "Cannot connect to cluster"
    exit 1
fi

echo ""

# 2. Check namespace exists
echo -e "${BLUE}2. Checking namespace...${NC}"
if kubectl get namespace todo-app >/dev/null 2>&1; then
    print_status 0 "Namespace 'todo-app' exists"
else
    print_status 1 "Namespace 'todo-app' not found"
    echo "Deploy with: ./deploy-to-k8s.sh"
    exit 1
fi

echo ""

# 3. Check deployments
echo -e "${BLUE}3. Checking deployments...${NC}"
DEPLOY=$(kubectl get deployment todo-backend -n todo-app 2>/dev/null)
if [ $? -eq 0 ]; then
    READY=$(kubectl get deployment todo-backend -n todo-app -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')
    echo -e "${GREEN}✓ Deployment found: $READY replicas ready${NC}"
else
    print_status 1 "Deployment not found"
fi

echo ""

# 4. Check pods
echo -e "${BLUE}4. Checking pods...${NC}"
PODS=$(kubectl get pods -n todo-app -o wide)
echo "$PODS"
echo ""

RUNNING=$(kubectl get pods -n todo-app --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
TOTAL=$(kubectl get pods -n todo-app --no-headers 2>/dev/null | wc -l)
echo -e "Pods: ${GREEN}$RUNNING/$TOTAL running${NC}\n"

# 5. Check services
echo -e "${BLUE}5. Checking services...${NC}"
kubectl get svc -n todo-app -o wide
echo ""

# 6. Check service endpoints
echo -e "${BLUE}6. Checking service endpoints...${NC}"
ENDPOINTS=$(kubectl get endpoints todo-backend-service -n todo-app -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)
if [ ! -z "$ENDPOINTS" ]; then
    print_status 0 "Service has endpoints: $ENDPOINTS"
else
    print_status 1 "Service has no endpoints"
fi

echo ""

# 7. Check LoadBalancer IP
echo -e "${BLUE}7. Checking LoadBalancer IP...${NC}"
LB_IP=$(kubectl get svc todo-backend-service -n todo-app -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
if [ ! -z "$LB_IP" ]; then
    echo -e "${GREEN}✓ LoadBalancer IP: $LB_IP${NC}"
    echo -e "${GREEN}✓ Access at: http://$LB_IP${NC}"
else
    echo -e "${YELLOW}⚠ LoadBalancer IP not assigned (pending)${NC}"
    echo "Use NodePort instead:"
    NODE_PORT=$(kubectl get svc todo-backend-service -n todo-app -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
    NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null)
    if [ ! -z "$NODE_IP" ] && [ ! -z "$NODE_PORT" ]; then
        echo -e "${GREEN}  http://$NODE_IP:$NODE_PORT${NC}"
    else
        echo "  Get node IP with: kubectl get nodes -o wide"
    fi
fi

echo ""

# 8. Check pod logs
echo -e "${BLUE}8. Checking pod logs...${NC}"
POD=$(kubectl get pod -n todo-app -l app=todo-backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ ! -z "$POD" ]; then
    echo -e "${GREEN}✓ Pod: $POD${NC}"
    echo "Recent logs:"
    kubectl logs "$POD" -n todo-app --tail=5
else
    print_status 1 "No pods found"
fi

echo ""

# 9. Check resource usage
echo -e "${BLUE}9. Checking resource usage...${NC}"
if kubectl top pods -n todo-app >/dev/null 2>&1; then
    kubectl top pods -n todo-app
else
    echo -e "${YELLOW}⚠ Metrics not available (install metrics-server)${NC}"
fi

echo ""

# 10. Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}\n"

if [ "$RUNNING" -gt 0 ]; then
    echo -e "${GREEN}✓ To-Do App is RUNNING on Kubernetes${NC}\n"
    echo "Your app is deployed and accessible!"
    echo ""
    if [ ! -z "$LB_IP" ]; then
        echo -e "Access URL: ${GREEN}http://$LB_IP${NC}"
    else
        echo "Use: kubectl get svc -n todo-app (to get service IP)"
    fi
else
    echo -e "${YELLOW}⚠ Pods are still initializing${NC}"
    echo "Wait a moment and run this script again."
fi

echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  Monitor logs:   kubectl logs -f deployment/todo-backend -n todo-app"
echo "  Watch pods:     watch kubectl get pods -n todo-app"
echo "  Scale app:      kubectl scale deployment todo-backend -n todo-app --replicas=3"
echo "  View events:    kubectl get events -n todo-app"
echo ""
