#!/bin/bash

# START KUBERNETES APPLICATION
# Simple one-command startup for Kubernetes deployment

echo "=========================================="
echo "Starting To-Do App on Kubernetes"
echo "=========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed!"
    exit 1
fi

# Check cluster connectivity
if ! kubectl cluster-info > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to Kubernetes cluster!"
    echo "Make sure your cluster is running."
    exit 1
fi

echo "Checking cluster..."
kubectl cluster-info > /dev/null

echo "Building Docker image..."
docker build -t todo-app:latest . > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "ERROR: Docker build failed!"
    exit 1
fi

echo "Deploying to Kubernetes..."
kubectl apply -f k8s-todo-deployment.yaml > /dev/null 2>&1

echo "Waiting for pods to start (this may take 30 seconds)..."
sleep 5

# Wait for pods to be running
for i in {1..30}; do
    RUNNING=$(kubectl get pods -n todo-app 2>/dev/null | grep -c "Running")
    TOTAL=$(kubectl get pods -n todo-app 2>/dev/null | grep "todo-backend" | wc -l)
    
    if [ "$RUNNING" -eq 2 ]; then
        break
    fi
    
    echo -n "."
    sleep 1
done

echo ""
echo ""

# Check if pods are running
if kubectl get pods -n todo-app 2>/dev/null | grep -q "Running"; then
    echo "=========================================="
    echo "✓ Kubernetes Application is RUNNING!"
    echo "=========================================="
    echo ""
    
    # Setup port forward
    echo "Setting up port forwarding..."
    kubectl port-forward svc/todo-backend-service 3001:80 -n todo-app > /dev/null 2>&1 &
    PORTFORWARD_PID=$!
    
    sleep 2
    
    echo ""
    echo "Access your app at:"
    echo "  http://localhost:3001"
    echo ""
    echo "Kubernetes Details:"
    echo "  Pods: 2 running"
    echo "  Namespace: todo-app"
    echo "  Auto-scaling: Enabled (2-5 pods)"
    echo ""
    echo "To view logs:"
    echo "  kubectl logs -f deployment/todo-backend -n todo-app"
    echo ""
    echo "To check pods:"
    echo "  kubectl get pods -n todo-app"
    echo ""
    echo "To stop the app:"
    echo "  run: stop-kubernetes.sh"
    echo ""
    
    # Keep port forward running
    wait $PORTFORWARD_PID
else
    echo "ERROR: Pods failed to start"
    echo "Check with: kubectl get pods -n todo-app"
    echo "View logs: kubectl logs deployment/todo-backend -n todo-app"
    exit 1
fi
