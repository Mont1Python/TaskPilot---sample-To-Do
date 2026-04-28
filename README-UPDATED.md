# To-Do Application - Complete Setup Guide

A full-stack To-Do application with Node.js backend, MongoDB database, and JWT authentication.

## Project Structure

```
├── server.js                      # Express backend
├── index.html                     # Frontend UI
├── package.json                   # Dependencies
├── Dockerfile                     # Container image definition
├── docker-compose.yml             # Local development setup
├── k8s-todo-deployment.yaml      # Kubernetes manifests
├── deploy-to-k8s.sh              # Kubernetes deployment script
├── verify-todo-k8s.sh            # Kubernetes verification script
├── setup-local.sh                # Local setup script
├── KUBERNETES_GUIDE.md           # Detailed Kubernetes guide
└── README.md                      # This file
```

## Quick Start

### Option 1: Run Locally (Docker Compose)

```bash
# Make setup script executable
chmod +x setup-local.sh

# Run setup (installs dependencies, builds image, starts containers)
./setup-local.sh

# Open in browser
# http://localhost:3001
```

**Stop the application:**
```bash
docker-compose down
```

### Option 2: Run on Kubernetes Cluster

**Prerequisites:**
- Kubernetes cluster running (1 master, 2 workers)
- `kubectl` configured and connected
- Docker installed

**Deploy:**
```bash
# Make deployment scripts executable
chmod +x deploy-to-k8s.sh verify-todo-k8s.sh

# Deploy to Kubernetes
./deploy-to-k8s.sh

# Verify deployment
./verify-todo-k8s.sh

# Check service IP
kubectl get svc -n todo-app
```

## Application Features

### User Management
- **Sign Up**: Create new account with email and password
- **Login**: JWT-based authentication
- **Profile**: Add tagline/bio to profile

### To-Do Management
- **Create Tasks**: Add new todos with:
  - Task text
  - List category (My Day, Work, Personal, etc.)
  - Sub-text/notes
  - Due date
  - Color coding
  - Important flag
- **Organize**: 
  - Multiple custom lists
  - Quick filters (My Day, Important, Planned, Completed, Overdue)
  - Rename/delete custom lists
- **Search**: Full-text search across tasks and notes
- **Manage**: Mark complete, update, delete tasks

### Data Persistence
- MongoDB cloud (Atlas) for data storage
- Per-user isolation (all data linked to user ID)
- Persistent across restarts

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | HTML/CSS/JavaScript | User interface |
| Backend | Node.js + Express | REST API server |
| Database | MongoDB Atlas | Cloud data storage |
| Authentication | JWT | Secure token-based auth |
| Containerization | Docker | Container images |
| Orchestration | Kubernetes | Container orchestration |
| Security | bcryptjs | Password hashing |

## API Endpoints

### Authentication
```
POST   /signup              # Create new user account
POST   /login               # Login and get JWT token
```

### User Profile
```
PUT    /user/profile        # Update user tagline
```

### To-Dos (CRUD)
```
GET    /todos               # Get all todos with optional filters
GET    /todos/:id           # Get specific todo
POST   /todos               # Create new todo
PUT    /todos/:id           # Update todo
DELETE /todos/:id           # Delete todo
```

### Queries & Search
```
GET    /todos/search?q=text # Search todos by text
GET    /lists/summary       # Get summary of all lists
```

### Lists Management
```
PUT    /lists/:oldName/rename  # Rename custom list
DELETE /lists/:name            # Delete custom list (moves tasks to My Day)
```

## Environment Variables

### Required
```
MONGODB_URI=mongodb://...          # MongoDB connection string
JWT_SECRET=your-secret-key         # JWT signing secret
```

### Optional
```
PORT=3001                          # Server port (default: 3001)
FRONTEND_URL=http://localhost:3001 # Frontend URL for CORS
NODE_ENV=production                # Node environment
```

These are set in `.env` file for local development and in Kubernetes Secret for cluster deployment.

## Docker Compose Development

**Start:**
```bash
docker-compose up
```

**Stop:**
```bash
docker-compose down
```

**Rebuild (after code changes):**
```bash
docker-compose build --no-cache
docker-compose up
```

**View logs:**
```bash
docker-compose logs -f backend
```

**Attach to running container:**
```bash
docker-compose exec backend sh
```

## Kubernetes Deployment Details

### What Gets Deployed
- **Namespace**: `todo-app` (isolates resources)
- **Deployment**: 2 replicas of todo-backend
- **Service**: LoadBalancer (exposes app to external traffic)
- **ConfigMap**: Non-sensitive config (PORT, FRONTEND_URL)
- **Secret**: Sensitive data (MongoDB URI, JWT Secret)
- **HPA**: Auto-scales between 2-5 replicas based on CPU/Memory
- **PDB**: Ensures at least 1 pod always running

### High Availability Features
- **Rolling Updates**: Zero-downtime deployments
- **Health Checks**:
  - Liveness probe: Restarts unhealthy containers
  - Readiness probe: Only routes traffic to ready pods
- **Resource Limits**: Prevents resource starvation
- **Auto-scaling**: Responds to traffic changes
- **Pod Disruption Budget**: Protects against cluster maintenance

### Monitoring Commands

**View pods:**
```bash
kubectl get pods -n todo-app -o wide
```

**Stream logs:**
```bash
kubectl logs -f deployment/todo-backend -n todo-app
```

**Watch in real-time:**
```bash
watch kubectl get pods -n todo-app
```

**Scale deployment:**
```bash
kubectl scale deployment todo-backend -n todo-app --replicas=5
```

**Check resource usage:**
```bash
kubectl top pods -n todo-app
```

**View all events:**
```bash
kubectl get events -n todo-app
```

**Rollback to previous version:**
```bash
kubectl rollout undo deployment/todo-backend -n todo-app
```

## Troubleshooting

### Application Won't Start Locally
```bash
# Check Docker daemon is running
docker ps

# Check logs
docker-compose logs backend

# Rebuild image
docker-compose build --no-cache

# Check MongoDB connection
# Verify MONGODB_URI in .env file
```

### Pods Not Starting on Kubernetes
```bash
# Check pod status
kubectl describe pod <pod-name> -n todo-app

# View logs
kubectl logs <pod-name> -n todo-app

# Check events
kubectl get events -n todo-app

# Common issues:
# - ImagePullBackOff: Rebuild and load image
# - CrashLoopBackOff: Check MongoDB URI and JWT_SECRET
# - Pending: Check node resources
```

### Cannot Connect to Database
```bash
# Verify MongoDB URI
kubectl get secret todo-app-secrets -n todo-app -o yaml | grep MONGODB_URI

# Test connection from pod
kubectl exec -it <pod-name> -n todo-app -- curl http://localhost:3001

# Check logs for connection errors
kubectl logs <pod-name> -n todo-app | grep -i "mongo\|connection"
```

### High Memory/CPU Usage
```bash
# Check current usage
kubectl top pods -n todo-app

# View resource limits
kubectl describe deployment todo-backend -n todo-app | grep -A 10 "Limits\|Requests"

# Scale up if needed
kubectl scale deployment todo-backend -n todo-app --replicas=5
```

## Security Considerations

### Implemented
- ✓ JWT-based authentication
- ✓ Password hashing with bcryptjs
- ✓ CORS protection
- ✓ Non-root Docker user
- ✓ Kubernetes secrets for sensitive data
- ✓ HTTPS ready (configure with Ingress)

### Recommended for Production
- [ ] Enable HTTPS/TLS
- [ ] Set up Ingress controller
- [ ] Configure network policies
- [ ] Enable Pod Security Standards
- [ ] Use external secrets manager (HashiCorp Vault)
- [ ] Set up audit logging
- [ ] Configure RBAC for Kubernetes access
- [ ] Use private container registry

## Performance Tuning

### Kubernetes HPA Configuration
Edit `k8s-todo-deployment.yaml`:
```yaml
minReplicas: 2              # Minimum pods to run
maxReplicas: 5              # Maximum pods allowed
cpu: 70%                    # Scale up at 70% CPU
memory: 80%                 # Scale up at 80% memory
```

### Resource Requests/Limits
```yaml
requests:
  cpu: 100m                 # Guaranteed minimum
  memory: 128Mi
limits:
  cpu: 500m                 # Maximum allowed
  memory: 256Mi
```

Adjust based on actual usage: `kubectl top pods -n todo-app`

## Next Steps

1. **Test Locally First**: Run with `./setup-local.sh`
2. **Deploy to Kubernetes**: Use `./deploy-to-k8s.sh`
3. **Monitor Cluster**: Use `./verify-todo-k8s.sh`
4. **Set up Ingress**: Configure domain/HTTPS access
5. **Enable Monitoring**: Add Prometheus + Grafana
6. **Configure CI/CD**: Use GitOps for automated deployments
7. **Add Backup Strategy**: Backup MongoDB regularly

## Useful Resources

- **Kubernetes**: https://kubernetes.io/docs/
- **Docker**: https://docs.docker.com/
- **Express.js**: https://expressjs.com/
- **MongoDB**: https://www.mongodb.com/docs/
- **JWT**: https://jwt.io/

## Support

For issues:
1. Check logs: `docker-compose logs` or `kubectl logs`
2. Run verification: `./verify-todo-k8s.sh`
3. Check environment variables are set correctly
4. Ensure MongoDB connection is valid
5. Review Kubernetes guide: `KUBERNETES_GUIDE.md`

## License

ISC

---

**Created for**: MCA Project - Full-Stack To-Do Application with Kubernetes Deployment
