# To-Do Application - Kubernetes Deployment Guide

## Project Overview
This is a full-stack To-Do application with:
- **Frontend**: HTML/CSS/JavaScript (served from Node.js)
- **Backend**: Express.js REST API
- **Database**: MongoDB (Atlas cloud)
- **Authentication**: JWT-based

## Files Added/Modified

### Kubernetes Files
- **k8s-todo-deployment.yaml** - Complete Kubernetes manifests including:
  - Namespace creation
  - ConfigMap for environment variables
  - Secret for sensitive data (MongoDB URI, JWT secret)
  - Deployment with 2 replicas
  - Service (LoadBalancer)
  - HorizontalPodAutoscaler (auto-scaling)
  - PodDisruptionBudget (high availability)

### Docker Files
- **Dockerfile** - Updated multi-stage build with:
  - Non-root user for security
  - Production-only dependencies
  - Health checks
  - Minimal Alpine image

- **docker-compose.yml** - Updated for local development with:
  - Volume mounts for hot reload
  - Networking setup
  - Environment configuration

### Deployment Scripts
- **deploy-to-k8s.sh** - Automated deployment script that:
  - Checks cluster connectivity
  - Builds Docker image
  - Loads image to cluster
  - Applies Kubernetes manifests
  - Waits for deployment to be ready
  - Displays access URLs

- **verify-todo-k8s.sh** - Verification script that:
  - Checks cluster connectivity
  - Verifies namespace and deployments
  - Shows pod status
  - Displays service information
  - Shows LoadBalancer IP or NodePort
  - Displays logs
  - Provides access URLs

## Quick Start

### Step 1: Run Locally with Docker Compose
```bash
# Install dependencies (if not already installed)
npm install

# Run with Docker Compose
docker-compose up

# Access at http://localhost:3001
```

### Step 2: Deploy to Kubernetes

#### Prerequisites
- Kubernetes cluster running (1 master, 2 workers)
- `kubectl` configured and connected to cluster
- Docker installed locally
- `kind` or `minikube` (for local clusters)

#### Deployment
```bash
# Make scripts executable
chmod +x deploy-to-k8s.sh verify-todo-k8s.sh

# Deploy to Kubernetes
./deploy-to-k8s.sh

# Verify deployment
./verify-todo-k8s.sh
```

## Kubernetes Features Included

### High Availability
- **2 Replicas**: Ensures app continues running if one pod fails
- **RollingUpdate**: Zero-downtime deployments
- **ReadinessProbe**: Only routes traffic to ready pods
- **LivenessProbe**: Automatically restarts unhealthy pods
- **PodDisruptionBudget**: Ensures minimum 1 pod always running

### Auto-Scaling
- **HorizontalPodAutoscaler (HPA)**:
  - Minimum 2 replicas
  - Maximum 5 replicas
  - Scales based on CPU (70%) and Memory (80%) usage
  - Automatically removes pods during low traffic

### Resource Management
- **Requests**: Guarantees minimum resources
  - CPU: 100m, Memory: 128Mi
- **Limits**: Prevents excessive resource usage
  - CPU: 500m, Memory: 256Mi

### Security
- **Non-root User**: Runs as nodejs user (UID 1001)
- **Security Context**: Drops unnecessary capabilities
- **Secrets Management**: MongoDB URI and JWT secret stored securely
- **Read-only filesystem**: Where possible

## Monitoring Your Deployment

### View All Pods
```bash
kubectl get pods -n todo-app -o wide
```

### View Deployment Status
```bash
kubectl get deployment -n todo-app
```

### View Services
```bash
kubectl get svc -n todo-app
```

### View Logs
```bash
# Stream logs from all pods
kubectl logs -f deployment/todo-backend -n todo-app

# View logs from specific pod
kubectl logs <pod-name> -n todo-app

# View last 100 lines
kubectl logs -n todo-app -l app=todo-backend --tail=100
```

### Watch Pods in Real-Time
```bash
watch kubectl get pods -n todo-app
```

### Check Pod Details
```bash
kubectl describe pod <pod-name> -n todo-app
```

## Managing the Deployment

### Scale Up/Down
```bash
# Scale to 3 replicas
kubectl scale deployment todo-backend -n todo-app --replicas=3

# View current replicas
kubectl get deployment todo-backend -n todo-app
```

### Rollout Status
```bash
# Check rollout progress
kubectl rollout status deployment/todo-backend -n todo-app

# View rollout history
kubectl rollout history deployment/todo-backend -n todo-app

# Rollback to previous version
kubectl rollout undo deployment/todo-backend -n todo-app
```

### Update Deployment
```bash
# Trigger a new rollout (useful for pulling new image)
kubectl rollout restart deployment/todo-backend -n todo-app
```

## Environment Variables

### ConfigMap (Non-sensitive)
- `PORT`: 3001
- `FRONTEND_URL`: http://localhost:3001

### Secret (Sensitive - in k8s-todo-deployment.yaml)
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: JWT signing secret

### To Update Secrets
```bash
# Update secret
kubectl create secret generic todo-app-secrets \
  --from-literal=MONGODB_URI="new-uri" \
  --from-literal=JWT_SECRET="new-secret" \
  -n todo-app \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart deployment to pick up new secrets
kubectl rollout restart deployment/todo-backend -n todo-app
```

## Accessing Your Application

### LoadBalancer IP (cloud/production)
```bash
# Get service IP
kubectl get svc todo-backend-service -n todo-app -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# Access at http://<IP>
```

### NodePort (local clusters)
```bash
# Get node port
kubectl get svc todo-backend-service -n todo-app -o jsonpath='{.spec.ports[0].nodePort}'

# Get node IP
kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}'

# Access at http://<node-ip>:<nodeport>
```

### Port Forward (quick testing)
```bash
kubectl port-forward svc/todo-backend-service 3001:80 -n todo-app

# Access at http://localhost:3001
```

## Troubleshooting

### Pods Not Starting
```bash
# Check pod status
kubectl describe pod <pod-name> -n todo-app

# View logs
kubectl logs <pod-name> -n todo-app

# Check events
kubectl get events -n todo-app
```

### ImagePullBackOff Error
- Ensure image is built: `docker build -t todo-app:latest .`
- For local clusters, load image: `kind load docker-image todo-app:latest`

### MongoDB Connection Issues
```bash
# Verify secret is set correctly
kubectl get secret todo-app-secrets -n todo-app -o yaml

# Check MongoDB URI in logs
kubectl logs deployment/todo-backend -n todo-app | grep "MongoDB"
```

### Service Not Accessible
```bash
# Check service endpoints
kubectl get endpoints -n todo-app

# Check service details
kubectl describe svc todo-backend-service -n todo-app

# Verify pod labels match service selector
kubectl get pods -n todo-app --show-labels
```

### High Memory/CPU Usage
```bash
# Check resource usage
kubectl top pods -n todo-app

# View resource requests/limits
kubectl describe deployment todo-backend -n todo-app | grep -A 10 "Limits\|Requests"

# Scale deployment if needed
kubectl scale deployment todo-backend -n todo-app --replicas=3
```

## Cleanup

### Delete Single Component
```bash
# Delete service
kubectl delete svc todo-backend-service -n todo-app

# Delete deployment
kubectl delete deployment todo-backend -n todo-app
```

### Delete Entire Namespace
```bash
# Deletes all resources in the namespace
kubectl delete namespace todo-app
```

## Next Steps

1. **Set up Ingress Controller**: Route external traffic with domains
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
   ```

2. **Enable Metrics Server**: For HPA to work with metrics
   ```bash
   kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
   ```

3. **Add Persistent Storage**: For data that should survive pod restarts
   ```yaml
   volumeMounts:
   - name: data
     mountPath: /data
   volumes:
   - name: data
     persistentVolumeClaim:
       claimName: todo-app-pvc
   ```

4. **Set up Monitoring**: Add Prometheus and Grafana for metrics

5. **Configure CI/CD**: Use GitOps (ArgoCD) for automated deployments

## Support

- Kubernetes Docs: https://kubernetes.io/docs/
- Express.js Docs: https://expressjs.com/
- MongoDB Atlas: https://www.mongodb.com/cloud/atlas
- Docker Docs: https://docs.docker.com/
