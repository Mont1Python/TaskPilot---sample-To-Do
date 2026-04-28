# Kubernetes Cluster Management Guide

## 📊 CHECK CLUSTER STATUS

### Quick Check (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File check-cluster-status.ps1
```

### Quick Check (Bash/Linux)
```bash
bash check-cluster-status.sh
```

### Manual Commands

**Check if cluster is running:**
```bash
kubectl cluster-info
```

**View all nodes:**
```bash
kubectl get nodes -o wide
```

**View node details:**
```bash
kubectl describe nodes
```

**View all pods:**
```bash
kubectl get pods -n todo-app -o wide
```

**View services:**
```bash
kubectl get svc -n todo-app
```

**View persistent volumes:**
```bash
kubectl get pvc -n todo-app
```

---

## 🚀 START CLUSTER

### Automatic (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File start-cluster.ps1
```

### Manual Method
```bash
# For Windows users with kind installed
kind export kubeconfig --name todo-cluster

# Wait a few seconds
$env:PATH = $env:PATH + ";" + $env:USERPROFILE
kind get clusters
```

### After Starting
```bash
# Verify cluster is running
kubectl cluster-info
kubectl get nodes

# Start port-forward to access app
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80

# Access at: http://localhost:8080
```

---

## ⏸️ PAUSE CLUSTER (Recommended for breaks)

### Automatic (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File pause-cluster.ps1
```

### What Happens
- ✅ All containers paused (not deleted)
- ✅ All data preserved
- ✅ Minimal CPU/memory used
- ✅ Can resume anytime with full state

### Manual Method
```bash
# Get container IDs
docker ps -a --filter "name=todo-cluster"

# Pause each container
docker pause <container_id>
```

---

## ▶️ RESUME CLUSTER (After pause)

### Automatic (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File resume-cluster.ps1
```

### Manual Method
```bash
# Get paused container IDs
docker ps -a --filter "status=paused" --filter "name=todo-cluster"

# Resume each container
docker unpause <container_id>

# Verify
kubectl cluster-info
```

---

## 🛑 STOP CLUSTER (Full shutdown)

### Automatic (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File stop-cluster.ps1
```

### What Happens
- ⚠️ Cluster deleted completely
- ✅ All data preserved in volumes
- ✅ Frees up all resources
- ⏰ Takes ~1-2 minutes to restart

### Manual Method
```bash
# Permanently delete the cluster
kind delete cluster --name todo-cluster

# Verify it's deleted
kind get clusters
```

### Restart After Stop
```bash
# Need to recreate the cluster
kind create cluster --config kind-config.yaml

# Redeploy the application
kubectl apply -f k8s-todo-deployment-final.yaml

# This takes ~5 minutes to be fully ready
```

---

## 📋 QUICK COMMAND REFERENCE

| Task | Command |
|------|---------|
| Check status | `powershell -ExecutionPolicy Bypass -File check-cluster-status.ps1` |
| Start cluster | `powershell -ExecutionPolicy Bypass -File start-cluster.ps1` |
| Pause cluster | `powershell -ExecutionPolicy Bypass -File pause-cluster.ps1` |
| Resume cluster | `powershell -ExecutionPolicy Bypass -File resume-cluster.ps1` |
| Stop cluster | `powershell -ExecutionPolicy Bypass -File stop-cluster.ps1` |
| View nodes | `kubectl get nodes -o wide` |
| View pods | `kubectl get pods -n todo-app -o wide` |
| View services | `kubectl get svc -n todo-app` |
| View logs | `kubectl logs -n todo-app <pod-name>` |
| Port-forward | `kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80` |

---

## 🎯 Recommended Workflow

### For Development (Daily Use)
```
Morning:
  1. Start cluster: start-cluster.ps1
  2. Check status: check-cluster-status.ps1
  3. Start port-forward: kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80
  4. Access app: http://localhost:8080

During Work:
  - Monitor: kubectl get pods -n todo-app -w
  - View logs: kubectl logs -n todo-app -f <pod-name>

End of Day:
  1. Stop port-forward (Ctrl+C in terminal)
  2. Pause cluster: pause-cluster.ps1
  3. Come back next day: resume-cluster.ps1
```

### For Extended Breaks
```
Option 1 (Pause - 5 seconds to resume):
  pause-cluster.ps1
  ... come back anytime ...
  resume-cluster.ps1

Option 2 (Stop - 2-5 minutes to restart):
  stop-cluster.ps1
  ... do other work ...
  start-cluster.ps1 (recreates if needed)
```

---

## 💾 SHOWING STATUS TO OTHERS

### Generate Status Report
```powershell
# Run this and share the output
powershell -ExecutionPolicy Bypass -File check-cluster-status.ps1 | Tee-Object -FilePath cluster-report.txt

# Share cluster-report.txt with others
```

### Screenshot Commands
```bash
# Take screenshots of these commands to show others:
1. kubectl get nodes -o wide
2. kubectl get pods -n todo-app -o wide
3. kubectl cluster-info
4. docker ps -a | grep todo-cluster
```

### Share Key Information
```
Cluster Name: todo-cluster
Nodes: 3 (1 master, 2 workers)
Status: ✅ Running / ⏸️ Paused / ❌ Stopped
Namespace: todo-app
App URL: http://localhost:8080
Pods Running: 3 (1 MongoDB, 2 Backend)
```

---

## ⚠️ TROUBLESHOOTING

### Cluster won't start
```bash
# Check kind installation
kind version

# Check Docker is running
docker ps

# Recreate from scratch
kind delete cluster --name todo-cluster
kind create cluster --config kind-config.yaml
kubectl apply -f k8s-todo-deployment-final.yaml
```

### Pods not coming up after pause/resume
```bash
# Check pod status
kubectl get pods -n todo-app

# View pod logs
kubectl logs -n todo-app <pod-name>

# Check MongoDB specifically
kubectl logs -n todo-app mongodb-0

# Restart deployment if needed
kubectl rollout restart deployment/todo-backend -n todo-app
```

### Port-forward not working
```bash
# Kill any existing port-forward
netstat -ano | findstr :8080 (Windows)
kill <PID>

# Restart port-forward
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80
```

### Out of disk space
```bash
# Clean up Docker resources
docker system prune -a

# This removes unused images and containers (keeps todo-cluster)
```

---

## 📊 RESOURCE USAGE

| State | CPU | Memory | Disk |
|-------|-----|--------|------|
| Running | High | 2-3GB | 5-10GB |
| Paused | Minimal | 100MB | 5-10GB |
| Stopped | None | 0MB | 5-10GB |

---

## 🔄 Full Cluster Lifecycle

```
CREATE → START → RUN → PAUSE → RESUME → RUN → PAUSE → ... → STOP → DELETE
  (1x)    (2s)   (∞)    (2s)    (2s)    (∞)  (2s)        (2s)   (1x)
```

- **CREATE:** `kind create cluster --config kind-config.yaml` (1 time)
- **START:** Resume from stopped state (2 seconds)
- **PAUSE:** Suspend execution (2 seconds, minimal resources)
- **RESUME:** Unpause containers (2 seconds)
- **STOP:** Delete cluster (2 seconds, data preserved)
- **DELETE:** Remove all traces (only if you don't need data)

---

## ✅ Best Practice

**Recommended:** Use PAUSE for daily work
- Fast to pause (2 seconds)
- Fast to resume (2 seconds)
- Minimal resource usage while paused
- All data and state preserved
- Can pause/resume multiple times per day

**Use STOP only when:**
- Need extended break (days/weeks)
- Want to free up significant disk space
- Won't need the cluster for a while

**Avoid DELETE unless:**
- Completely sure you don't need the data
- Want completely clean slate for fresh deployment
