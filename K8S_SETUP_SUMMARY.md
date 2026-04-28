# Kubernetes Cluster Setup Complete

## Cluster Information

**Cluster Name:** todo-cluster
**Kubernetes Version:** v1.28.0
**Node Configuration:**
- 1 Master (Control Plane): todo-cluster-control-plane
- 2 Workers: todo-cluster-worker, todo-cluster-worker2

## Deployment Details

### Namespace: todo-app

#### MongoDB StatefulSet
- **Name:** mongodb-0
- **Node:** todo-cluster-worker
- **Status:** Running
- **Service:** mongodb-service (ClusterIP: None, Port: 27017)
- **Storage:** 1Gi persistent volume

#### To-Do Backend Deployment
- **Replicas:** 2 (distributed across worker nodes)
  - Pod 1: todo-backend-5849c9f989-jk5fw (worker)
  - Pod 2: todo-backend-5849c9f989-qqfmh (worker2)
- **Status:** Running
- **Image:** todo-app:latest
- **Ports:** 3001 (internal), 80 (service), 30001 (NodePort external)

#### Services
1. **todo-backend-service** - ClusterIP (internal communication)
2. **todo-frontend-lb** - NodePort 30001 (external access)
3. **mongodb-service** - Headless ClusterIP (StatefulSet)

#### Configuration
- **ConfigMap:** todo-app-config
- **Secret:** todo-app-secrets
- **Resource Limits:**
  - Backend: 256Mi memory, 500m CPU
  - MongoDB: 512Mi memory, 500m CPU

#### Autoscaling
- **HPA (Horizontal Pod Autoscaler):**
  - Min Replicas: 2
  - Max Replicas: 5
  - CPU Target: 70%
  - Memory Target: 80%

#### High Availability
- **Pod Disruption Budget:** Minimum 1 pod available
- **Pod Anti-Affinity:** Pods spread across different nodes
- **Rolling Update Strategy:** maxSurge=1, maxUnavailable=0

## Accessing the Application

### Option 1: Port-Forward (Local Development)
```bash
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80
# Access at http://localhost:8080
```

### Option 2: NodePort Direct Access
```bash
# Access at http://localhost:30001
# (or your node IP:30001)
```

### Option 3: Cluster Internal
```bash
# From within cluster: http://todo-backend-service:80
# For MongoDB: mongodb-service:27017
```

## Useful Commands

### View All Resources
```bash
kubectl get all -n todo-app
```

### Pod Logs
```bash
# Backend logs
kubectl logs -n todo-app <pod-name>

# Follow logs
kubectl logs -n todo-app <pod-name> -f
```

### Pod Status
```bash
kubectl describe pod -n todo-app <pod-name>
```

### Check Pod Distribution
```bash
kubectl get pods -n todo-app -o wide
```

### Check Node Status
```bash
kubectl get nodes -o wide
```

### Scale Deployment Manually
```bash
kubectl scale deployment todo-backend -n todo-app --replicas=3
```

### Delete Deployment
```bash
kubectl delete namespace todo-app
```

## Environment Variables

### Backend Configuration
- **PORT:** 3001
- **FRONTEND_URL:** http://localhost
- **NODE_ENV:** production
- **MONGODB_URI:** mongodb://mongodb-service:27017/tododb
- **JWT_SECRET:** (from Secret)

## Notes

1. MongoDB is running without authentication (suitable for development/testing)
2. Data persists in the StatefulSet volume (1Gi)
3. Backend replicas use Pod Anti-Affinity to spread across workers
4. HPA will scale replicas based on CPU and memory metrics
5. Rolling updates ensure zero downtime deployments
6. All traffic between services uses internal Kubernetes DNS

## Next Steps

- Configure persistent storage class if needed
- Set up ingress controller for external access
- Enable authentication in MongoDB for production
- Set up monitoring (Prometheus/Grafana)
- Configure backup strategy for MongoDB
- Set up CI/CD pipelines for automated deployments
