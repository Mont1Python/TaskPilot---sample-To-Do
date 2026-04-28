#!/bin/bash
# Check Kubernetes cluster status and nodes

echo "================================"
echo "KUBERNETES CLUSTER STATUS"
echo "================================"
echo ""

# Check if cluster exists
echo "Checking cluster..."
CLUSTER_EXISTS=$(kubectl cluster-info 2>&1 | grep -i "running\|online" | wc -l)

if [ $CLUSTER_EXISTS -eq 0 ]; then
    echo "❌ Cluster is NOT running"
    exit 1
fi

echo "✅ Cluster is RUNNING"
echo ""

# Get cluster info
echo "================================"
echo "CLUSTER INFORMATION"
echo "================================"
kubectl cluster-info

echo ""
echo "================================"
echo "NODES STATUS"
echo "================================"
kubectl get nodes -o wide

echo ""
echo "================================"
echo "NODE DETAILS"
echo "================================"
kubectl describe nodes

echo ""
echo "================================"
echo "POD STATUS (todo-app namespace)"
echo "================================"
kubectl get pods -n todo-app -o wide

echo ""
echo "================================"
echo "SERVICES"
echo "================================"
kubectl get svc -n todo-app

echo ""
echo "================================"
echo "RESOURCE USAGE"
echo "================================"
kubectl top nodes 2>/dev/null || echo "Metrics not available"
kubectl top pods -n todo-app 2>/dev/null || echo "Pod metrics not available"

echo ""
echo "================================"
echo "STORAGE"
echo "================================"
kubectl get pvc -n todo-app

echo ""
echo "Status Report Generated: $(date)"
