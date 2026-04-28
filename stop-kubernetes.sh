#!/bin/bash

# STOP KUBERNETES APPLICATION
# Simple one-command shutdown

echo "=========================================="
echo "Stopping To-Do App from Kubernetes"
echo "=========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed!"
    exit 1
fi

# Check if namespace exists
if kubectl get namespace todo-app > /dev/null 2>&1; then
    echo "Deleting Kubernetes deployment..."
    kubectl delete namespace todo-app
    
    echo ""
    echo "=========================================="
    echo "✓ Kubernetes Application STOPPED"
    echo "=========================================="
    echo ""
    echo "All resources deleted:"
    echo "  - Pods removed"
    echo "  - Service removed"
    echo "  - Deployments removed"
    echo "  - Namespace removed"
    echo ""
    echo "To start again:"
    echo "  run: start-kubernetes.sh"
    echo ""
else
    echo "Kubernetes application is not running"
    echo "Namespace 'todo-app' does not exist"
    exit 0
fi
