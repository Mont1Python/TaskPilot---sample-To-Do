# Kubernetes Cluster Setup - Complete Guide

## ✅ Cluster Status

Your to-do application is now running on a 3-node Kubernetes cluster with 1 master and 2 worker nodes.

### Nodes
```
Master: todo-cluster-control-plane
Worker 1: todo-cluster-worker
Worker 2: todo-cluster-worker2
Kubernetes Version: v1.28.0
```

### Running Pods
```
mongodb-0                    - MongoDB database (on worker1)
todo-backend-XXXXX           - Backend Pod 1 (on worker2)
todo-backend-XXXXX           - Backend Pod 2 (on worker1)
```

---

## 📋 Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
├─────────────┬──────────────────────────┬────────────────────┤
│   Master    │      Worker 1            │      Worker 2      │
│  (Control   │  (todo-cluster-worker)   │(todo-cluster-     │
│   Plane)    │                          │   worker2)         │
│             │                          │                    │
│             │ ┌──────────────────────┐ │ ┌──────────────┐  │
│             │ │ MongoDB Pod          │ │ │ Todo Backend │  │
│             │ │ (StatefulSet)        │ │ │ Pod 1        │  │
│             │ │ Port: 27017          │ │ │ Port: 3001   │  │
│             │ └──────────────────────┘ │ └──────────────┘  │
│             │                          │                    │
│             │ ┌──────────────────────┐ │ ┌──────────────┐  │
│             │ │ Todo Backend Pod 2   │ │ │ (Headless)   │  │
│             │ │ Port: 3001           │ │ │ Service DNS  │  │
│             │ └──────────────────────┘ │ └──────────────┘  │
│             │                          │                    │
└─────────────┴──────────────────────────┴────────────────────┘
                          ↓
              ┌───────────────────────────┐
              │   Services (ClusterIP)    │
              ├───────────────────────────┤
              │ todo-backend-service:80   │
              │ mongodb-service:27017     │
              │ todo-frontend-lb:30001    │
              │ (NodePort for external)   │
              └───────────────────────────┘
```

---

## 🚀 How to Access the Application

### Option 1: Port-Forward (Recommended for Development)
This tunnels the service through your local machine:

```bash
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80
```

Then access at: **http://localhost:8080**

**The cluster is already running port-forward in the background on port 8080**

### Option 2: Direct Access (from kind cluster)
```bash
# Inside kind nodes only:
http://todo-backend-service:80
```

### Option 3: Browser Test Interface
Open the provided test file: **k8s-test.html**
- Default endpoint: http://localhost:8080
- Test signup, login, and create to-dos
- View API responses in real-time

---

## 📡 API Endpoints

All endpoints available at base URL (default: **http://localhost:8080**)

### Authentication
```
POST /signup
  Body: { name, email, password }
  Returns: { user, token }

POST /login
  Body: { email, password }
  Returns: { user, token }
```

### To-Dos
```
GET /todos?list=My Day
  Headers: Authorization: Bearer <token>
  Returns: Array of todos

POST /todos
  Headers: Authorization: Bearer <token>
  Body: { text, list, subText, isImportant, dueDate, type, checklistItems }
  Returns: Created todo object

PUT /todos/:id
  Headers: Authorization: Bearer <token>
  Body: { text, list, subText, completed, ... }
  Returns: Updated todo object

DELETE /todos/:id
  Headers: Authorization: Bearer <token>
  Returns: 204 No Content
```

### Lists
```
GET /lists/summary
  Headers: Authorization: Bearer <token>
  Returns: Summary counts for all lists

PUT /lists/:oldName/rename
  Headers: Authorization: Bearer <token>
  Body: { newName }
  Returns: Count of modified items

DELETE /lists/:name
  Headers: Authorization: Bearer <token>
  Returns: Count of moved items
```

---

## 🔧 Useful Kubernetes Commands

### View Cluster Resources
```bash
# All resources in todo-app namespace
kubectl get all -n todo-app

# Nodes and their status
kubectl get nodes -o wide

# Pods with node assignment
kubectl get pods -n todo-app -o wide

# Services and their ports
kubectl get svc -n todo-app

# StatefulSets
kubectl get statefulsets -n todo-app

# Deployments
kubectl get deployments -n todo-app

# Horizontal Pod Autoscaler status
kubectl get hpa -n todo-app
```

### Debugging
```bash
# View pod logs
kubectl logs -n todo-app <pod-name>

# Follow logs in real-time
kubectl logs -n todo-app <pod-name> -f

# Describe a pod (shows events, status, resource usage)
kubectl describe pod -n todo-app <pod-name>

# Shell into a pod
kubectl exec -it -n todo-app <pod-name> -- /bin/sh

# Check service endpoints
kubectl get endpoints -n todo-app
```

### Management
```bash
# Restart pods
kubectl rollout restart deployment/todo-backend -n todo-app

# Scale replicas
kubectl scale deployment todo-backend -n todo-app --replicas=4

# Delete everything
kubectl delete namespace todo-app

# Watch pod status changes
kubectl get pods -n todo-app -w
```

---

## 📊 Monitoring & Scaling

### Horizontal Pod Autoscaling
The cluster is configured with HPA that automatically scales replicas based on:
- **CPU Utilization:** 70% threshold
- **Memory Utilization:** 80% threshold
- **Min Replicas:** 2
- **Max Replicas:** 5

Current HPA status:
```bash
kubectl get hpa -n todo-app -w
```

### Pod Disruption Budget
Ensures minimum 1 pod is always available during updates:
```bash
kubectl get pdb -n todo-app
```

### Resource Limits
```
Backend Pod:
  Memory Request: 128Mi
  Memory Limit: 256Mi
  CPU Request: 100m
  CPU Limit: 500m

MongoDB Pod:
  Memory Request: 256Mi
  Memory Limit: 512Mi
  CPU Request: 250m
  CPU Limit: 500m
```

---

## 🗄️ Database Configuration

### MongoDB
- **Service Name:** mongodb-service
- **Internal Port:** 27017
- **Storage:** 1Gi PersistentVolume
- **Authentication:** None (dev mode)
- **Command:** `mongod --bind_ip_all`

Connection string (from backend):
```
mongodb://mongodb-service:27017/tododb
```

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `kind-config.yaml` | Kind cluster configuration (1 master, 2 workers) |
| `k8s-todo-deployment-final.yaml` | All Kubernetes manifests (Deployment, StatefulSet, Services, ConfigMap, Secret, HPA, PDB) |
| `k8s-test.html` | Interactive browser-based API tester |
| `server.js` | Fixed backend with CORS enabled |
| `Dockerfile` | Multi-stage Node.js image |
| `K8S_SETUP_SUMMARY.md` | Previous setup reference |

---

## 🔐 Secrets & Configuration

### Stored in Kubernetes Secret: `todo-app-secrets`
```yaml
MONGODB_URI: "mongodb://mongodb-service:27017/tododb"
JWT_SECRET: "bd7aca6f3a..." (production use unique values)
```

### Stored in ConfigMap: `todo-app-config`
```yaml
PORT: "3001"
FRONTEND_URL: "http://localhost"
NODE_ENV: "production"
```

---

## ⚙️ Network Architecture

### Internal Kubernetes DNS
```
mongodb-service:27017      → Headless service for StatefulSet
todo-backend-service:80    → ClusterIP for internal access
```

### External Access
```
NodePort: 30001            → Exposed on Kubernetes nodes
Port-Forward: 8080         → Local tunnel through kubectl
```

### CORS Configuration
Backend accepts requests from:
- `*` (all origins) in development mode
- Ensure frontend URL matches for production

---

## 🚨 Troubleshooting

### Backend pods keep restarting
```bash
# Check logs
kubectl logs -n todo-app <pod-name>

# Common issues:
# 1. MongoDB not ready - check mongodb-0 status
# 2. Connection string wrong - verify MONGODB_URI in secret
# 3. Port already in use - change in ConfigMap
```

### Cannot reach the application
```bash
# 1. Ensure port-forward is running:
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80

# 2. Check service is running:
kubectl get svc -n todo-app

# 3. Verify backend pods are ready:
kubectl get pods -n todo-app
```

### Database connectivity issues
```bash
# Test MongoDB connection:
kubectl exec -it -n todo-app mongodb-0 -- mongosh

# Check service endpoints:
kubectl get endpoints -n todo-app
```

---

## 🎯 Next Steps

1. **Test the API:** Open `k8s-test.html` in your browser
2. **Create Users:** Use signup endpoint to create test accounts
3. **Add To-Dos:** Create tasks through the API
4. **Monitor Scaling:** Watch `kubectl get hpa -n todo-app -w`
5. **Production Setup:**
   - Enable MongoDB authentication
   - Use managed database instead of StatefulSet
   - Set up Ingress controller for better routing
   - Configure persistent storage class
   - Add monitoring (Prometheus/Grafana)
   - Set up backup strategy
   - Use sealed secrets for sensitive data

---

## 📞 Quick Reference

```bash
# Start port-forward
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80

# Watch all pods
kubectl get pods -n todo-app -w

# Check cluster health
kubectl get nodes
kubectl cluster-info

# View all resources
kubectl get all -n todo-app

# Delete cluster (if needed)
kind delete cluster --name todo-cluster
```

---

**Setup Status: ✅ Complete**
**Last Updated:** 2026-04-28
**Cluster Version:** Kubernetes v1.28.0
