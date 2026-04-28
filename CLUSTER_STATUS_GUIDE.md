# CLUSTER STATUS & MANAGEMENT - Complete Guide

## 🟢 CURRENT CLUSTER STATUS (LIVE)

### Nodes ✅
```
todo-cluster-control-plane   Ready    control-plane   (Master)
todo-cluster-worker          Ready    <none>          (Worker 1)
todo-cluster-worker2         Ready    <none>          (Worker 2)
Kubernetes Version: v1.28.0
Status: ALL NODES RUNNING
```

### Pods Running ✅
```
mongodb-0                       1/1 Running  (Database)
todo-backend-5849c9f989-9phbr   1/1 Running  (API - Worker 2)
todo-backend-5849c9f989-wb2fq   1/1 Running  (API - Worker 1)
Status: ALL PODS HEALTHY
```

---

## 📊 CHECK CLUSTER STATUS - 3 WAYS

### Method 1: Automated Dashboard (EASIEST)
```powershell
powershell -ExecutionPolicy Bypass -File cluster-dashboard.ps1
```
- Real-time updates every 5 seconds
- Shows nodes, pods, services
- Color-coded status
- Press Ctrl+C to exit

### Method 2: Status Report (For Sharing)
```powershell
powershell -ExecutionPolicy Bypass -File export-status-report.ps1
```
- Generates `cluster-status-report.txt`
- Share with team members
- Complete cluster information
- No browser needed

### Method 3: Full Check (Detailed)
```powershell
powershell -ExecutionPolicy Bypass -File check-cluster-status.ps1
```
- Comprehensive cluster information
- All nodes, pods, services, storage
- Resource usage (if available)
- One-time report

---

## 🎮 MANAGE CLUSTER - 4 OPERATIONS

### OPERATION 1: START CLUSTER
**When:** After stopping the cluster

```powershell
powershell -ExecutionPolicy Bypass -File start-cluster.ps1
```

**What happens:**
- Verifies Docker is running
- Exports kubeconfig
- Waits for cluster to be ready
- Shows current status

**Time:** 30-60 seconds
**Data:** Restored from previous state

---

### OPERATION 2: PAUSE CLUSTER ⭐ RECOMMENDED
**When:** Taking a break (5 min to 8 hours)

```powershell
powershell -ExecutionPolicy Bypass -File pause-cluster.ps1
```

**What happens:**
- All containers paused (not deleted)
- Data fully preserved
- Minimal CPU/memory used (~100MB)
- Can resume anytime

**Time:** 2 seconds to pause, 2 seconds to resume
**Resources:** Minimal - just disk space
**Best for:** Daily work, meetings, lunch breaks

---

### OPERATION 3: RESUME CLUSTER
**When:** Restarting after pause

```powershell
powershell -ExecutionPolicy Bypass -File resume-cluster.ps1
```

**What happens:**
- Resumes all paused containers
- Restores full cluster state
- All applications restart
- Ready to use immediately

**Time:** 2-5 seconds
**Data:** Fully restored
**Pods:** All start automatically

---

### OPERATION 4: STOP CLUSTER
**When:** Extended break (days/weeks) or want to free resources

```powershell
powershell -ExecutionPolicy Bypass -File stop-cluster.ps1
```

**What happens:**
- Cluster completely deleted
- All data preserved in volumes
- Frees CPU, memory, and most disk
- Can restart from scratch

**Time:** 2-5 seconds to stop
**Restart time:** 1-2 minutes (full initialization)
**Data:** Preserved - nothing lost

---

## 📅 RECOMMENDED USAGE PATTERNS

### Daily Work (Recommended)
```
Morning:
  1. powershell -ExecutionPolicy Bypass -File start-cluster.ps1
  2. powershell -ExecutionPolicy Bypass -File cluster-dashboard.ps1
  3. kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80
  4. Open browser: http://localhost:8080

During work:
  - Keep dashboard open
  - Monitor logs: kubectl logs -n todo-app -f <pod>
  - View metrics: kubectl top pods -n todo-app

Lunch/Break (5 min - 2 hours):
  1. Pause: powershell -ExecutionPolicy Bypass -File pause-cluster.ps1
  2. Take break
  3. Resume: powershell -ExecutionPolicy Bypass -File resume-cluster.ps1

End of Day:
  1. Stop: powershell -ExecutionPolicy Bypass -File stop-cluster.ps1
  2. Come back tomorrow - all data preserved
```

### Weekend/Extended Break
```
Before leaving (Friday):
  1. Export report: powershell -ExecutionPolicy Bypass -File export-status-report.ps1
  2. Stop cluster: powershell -ExecutionPolicy Bypass -File stop-cluster.ps1
  3. All data preserved, minimal resources used

Coming back (Monday):
  1. Start: powershell -ExecutionPolicy Bypass -File start-cluster.ps1
  2. Everything is exactly as you left it!
```

---

## 🎯 QUICK COMMANDS FOR SHOWING TO OTHERS

### Show current status (snapshot)
```bash
kubectl get nodes -o wide
kubectl get pods -n todo-app -o wide
kubectl get svc -n todo-app
```

### Show in real-time (live updates)
```powershell
powershell -ExecutionPolicy Bypass -File cluster-dashboard.ps1
# Press Ctrl+C to exit
```

### Export report to share
```powershell
powershell -ExecutionPolicy Bypass -File export-status-report.ps1
# Share cluster-status-report.txt via email/chat
```

### Show cluster info
```bash
kubectl cluster-info
kubectl describe nodes
```

---

## 📋 MANUAL COMMANDS (If scripts don't work)

### Check Status
```bash
kubectl cluster-info
kubectl get nodes
kubectl get pods -n todo-app
kubectl get svc -n todo-app
```

### View Details
```bash
kubectl describe nodes
kubectl describe pod -n todo-app <pod-name>
kubectl logs -n todo-app <pod-name>
```

### List Clusters
```bash
kind get clusters
docker ps -a | grep todo-cluster
```

### Pause/Resume (Docker level)
```bash
# List containers
docker ps -a --filter "name=todo-cluster"

# Pause all
docker ps -a --filter "name=todo-cluster" -q | foreach { docker pause $_ }

# Resume all
docker ps -a --filter "status=paused" -q | foreach { docker unpause $_ }
```

---

## ⚡ QUICK REFERENCE TABLE

| Task | Time | Command | Resource Impact |
|------|------|---------|-----------------|
| Check Status | 5s | `check-cluster-status.ps1` | None |
| Dashboard | ∞ | `cluster-dashboard.ps1` | Minimal |
| Export Report | 10s | `export-status-report.ps1` | None |
| Start | 30s | `start-cluster.ps1` | None (already running) |
| Pause | 2s | `pause-cluster.ps1` | 5GB disk + 100MB RAM |
| Resume | 2s | `resume-cluster.ps1` | Brings back to full |
| Stop | 5s | `stop-cluster.ps1` | 5GB disk only |
| Restart after stop | 2min | `start-cluster.ps1` | None to full |

---

## 🔍 UNDERSTANDING THE DASHBOARD

When you run the dashboard, you'll see:

```
NODES SECTION:
  ✅ todo-cluster-control-plane (Master)
  ✅ todo-cluster-worker (Worker 1)
  ✅ todo-cluster-worker2 (Worker 2)
  
PODS SECTION:
  ✅ mongodb-0 (Database)
  ✅ todo-backend-XXXXX (API Pod 1)
  ✅ todo-backend-XXXXX (API Pod 2)
  
SERVICES SECTION:
  ✅ mongodb-service (Internal)
  ✅ todo-backend-service (Internal)
  ✅ todo-frontend-lb (External on port 30001)
```

All green checkmarks = Everything working!

---

## 🚨 TROUBLESHOOTING

### Cluster won't start
```bash
# Check if Docker is running
docker ps

# Check kind clusters
kind get clusters

# Verify kind installation
kind version
```

### Pods not running
```bash
# Check pod status
kubectl get pods -n todo-app

# View pod logs
kubectl logs -n todo-app <pod-name>

# Describe pod for errors
kubectl describe pod -n todo-app <pod-name>
```

### Can't connect to app
```bash
# Start port-forward
kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80

# Verify service is running
kubectl get svc -n todo-app

# Check app responds
curl http://localhost:8080
```

### Out of resources
```bash
# Stop cluster to free up
powershell -ExecutionPolicy Bypass -File stop-cluster.ps1

# Clean up Docker
docker system prune -a
```

---

## 📊 RESOURCE USAGE BY STATE

| State | CPU | Memory | Disk | Can Resume |
|-------|-----|--------|------|-----------|
| Running | 20-30% | 2-3GB | 5-10GB | N/A |
| Paused | 0% | 100MB | 5-10GB | Yes (2s) |
| Stopped | 0% | 0MB | 5-10GB | Yes (2min) |

**Recommendation:** Use PAUSE for daily breaks to maintain state without consuming resources.

---

## ✨ SHOWING TO OTHERS

### In a Meeting/Presentation
```
1. Open dashboard:
   powershell -ExecutionPolicy Bypass -File cluster-dashboard.ps1

2. Show them:
   - 3 nodes running
   - 3 pods healthy
   - Services operational
   - Real-time updates
```

### In Email/Chat
```
1. Generate report:
   powershell -ExecutionPolicy Bypass -File export-status-report.ps1

2. Attach: cluster-status-report.txt

3. Share via email/Slack/Teams
```

### In Documentation
```
1. Export report with timestamp
2. Add screenshots of dashboard
3. Include commands they can run
4. Document cluster architecture
```

---

## 🎓 BEST PRACTICES

✅ **DO:**
- Pause during breaks (saves resources)
- Check dashboard regularly
- Export reports before important changes
- Stop cluster on weekends
- Keep port-forward in separate terminal

❌ **DON'T:**
- Leave cluster running 24/7
- Ignore pod restarts
- Delete cluster data unless certain
- Forget to pause/stop
- Run multiple clusters unnecessarily

---

**Summary:**
- Check status: `cluster-dashboard.ps1`
- Daily work: Start → Pause → Resume → Stop cycle
- Share with others: `export-status-report.ps1`
- All data preserved during pause/stop
- Minimal resources when paused
