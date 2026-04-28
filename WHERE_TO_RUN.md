# WHERE TO RUN - Visual Guide

## Your Project Location
```
📁 G:\MCA Project\To-Do sample updated\To-Do sample\
   ├── 📄 server.js (Node.js backend)
   ├── 📄 index.html (Frontend UI)
   ├── 📄 Dockerfile (Container image)
   ├── 📄 docker-compose.yml (Local setup)
   ├── 📄 k8s-todo-deployment.yaml (Kubernetes config)
   ├── 📄 setup-local.sh (Run locally)
   ├── 📄 deploy-to-k8s.sh (Run on Kubernetes)
   ├── 📄 verify-todo-k8s.sh (Check status)
   ├── 📄 QUICK_START.txt (This file)
   └── 📄 .env (MongoDB config)
```

## How to Access

### METHOD 1: Run Locally on Your Computer

```
┌─────────────────────────────────────┐
│   Your Windows Computer             │
│                                     │
│  PowerShell/CMD                     │
│  $ cd G:\MCA Project\...            │
│  $ docker-compose up                │
│                                     │
│  ┌─────────────────────────┐        │
│  │  Docker Container       │        │
│  │  ┌─────────────────┐    │        │
│  │  │  Node.js App    │    │        │
│  │  │  Port: 3001     │    │        │
│  │  └─────────────────┘    │        │
│  └─────────────────────────┘        │
│           ↓                         │
│    Open Browser                     │
│    http://localhost:3001            │
└─────────────────────────────────────┘
         ↓
    ┌────────────────────┐
    │ MongoDB Cloud      │
    │ (Atlas)            │
    │ Your data stored   │
    └────────────────────┘
```

### METHOD 2: Run on Kubernetes Cluster

```
┌─────────────────────────────────────────────────────────────┐
│   Kubernetes Cluster                                        │
│   (1 Master Node + 2 Worker Nodes)                         │
│                                                             │
│   Master Node                                              │
│   ┌──────────────────────┐                                │
│   │ Control Plane        │                                │
│   │ etcd, scheduler      │                                │
│   └──────────────────────┘                                │
│                                                             │
│   Worker Node 1          Worker Node 2                     │
│   ┌─────────────────┐    ┌─────────────────┐             │
│   │ Pod: todo-app-1 │    │ Pod: todo-app-2 │             │
│   │ Port: 3001      │    │ Port: 3001      │             │
│   └─────────────────┘    └─────────────────┘             │
│           ↓                      ↓                         │
│   ┌──────────────────────────────────────┐               │
│   │  Kubernetes Service (LoadBalancer)  │               │
│   │  http://<EXTERNAL-IP>               │               │
│   └──────────────────────────────────────┘               │
│                                                             │
│   HPA (Auto-Scale: 2-5 pods)                              │
│   PDB (Min 1 pod always running)                          │
└─────────────────────────────────────────────────────────────┘
         ↓
    ┌────────────────────┐
    │ MongoDB Cloud      │
    │ (Atlas)            │
    │ Your data stored   │
    └────────────────────┘
```

## Step-by-Step Instructions

### LOCAL SETUP (Easiest - Do This First!)

**Step 1: Open PowerShell**
- Press: `Win + R`
- Type: `powershell`
- Press: `Enter`

**Step 2: Navigate to Project**
```powershell
cd "G:\MCA Project\To-Do sample updated\To-Do sample"
```

**Step 3: Run Setup**
```powershell
docker-compose up
```

**Step 4: Wait for Output**
```
Creating network "to-do_todo-network" with driver "bridge"
Building backend
[+] Building 45.2s (11/11) FINISHED
...
To-Do List Backend API running on http://localhost:3001
```

**Step 5: Open Browser**
- Go to: `http://localhost:3001`
- You should see the To-Do app UI

**Step 6: Test It**
- Click "Sign Up"
- Enter email and password
- Add some to-do items
- Verify it works!

**Step 7: Stop It (When Done)**
- In PowerShell: Press `Ctrl + C`
- Or run: `docker-compose down`

---

### KUBERNETES SETUP (After Local Testing Works!)

**Prerequisites:**
```
✓ Kubernetes cluster must be running (1 master + 2 workers)
✓ kubectl must be installed and configured
✓ Docker must be installed
✓ App must work locally first (test with docker-compose)
```

**Step 1: Verify Cluster is Running**
```powershell
kubectl cluster-info
# Should show cluster info, not error
```

**Step 2: Navigate to Project**
```powershell
cd "G:\MCA Project\To-Do sample updated\To-Do sample"
```

**Step 3: Deploy to Kubernetes**
```powershell
./deploy-to-k8s.sh
```

**Step 4: Wait for Deployment**
```
Building Docker image...
✓ Docker image built successfully

Loading image to cluster...
✓ Image loaded to cluster

Applying Kubernetes manifests...
✓ Kubernetes manifests applied

Waiting for deployments to be ready...
deployment.apps/todo-backend rolled out successfully
```

**Step 5: Verify Deployment**
```powershell
./verify-todo-k8s.sh
```

**Step 6: Get Access URL**
```powershell
kubectl get svc -n todo-app
```

Look for `todo-backend-service` EXTERNAL-IP. Open that IP in browser.

**Step 7: Monitor**
```powershell
# Watch pods
watch kubectl get pods -n todo-app

# View logs
kubectl logs -f deployment/todo-backend -n todo-app

# Check status
kubectl get all -n todo-app
```

---

## Common Commands Reference

### LOCAL (Docker Compose)

| Command | What it does |
|---------|-------------|
| `docker-compose up` | Start the app |
| `docker-compose down` | Stop the app |
| `docker-compose logs backend` | View logs |
| `docker-compose ps` | Check status |
| `docker-compose build --no-cache` | Rebuild after code changes |

### KUBERNETES

| Command | What it does |
|---------|-------------|
| `./deploy-to-k8s.sh` | Deploy to cluster |
| `./verify-todo-k8s.sh` | Check deployment status |
| `kubectl get pods -n todo-app` | List all pods |
| `kubectl logs -f deployment/todo-backend -n todo-app` | Stream logs |
| `kubectl get svc -n todo-app` | Get service IP |
| `kubectl scale deployment todo-backend -n todo-app --replicas=3` | Scale to 3 pods |
| `kubectl delete namespace todo-app` | Delete everything |

---

## What Each File Does

| File | Purpose | When Used |
|------|---------|-----------|
| `server.js` | Node.js backend API | Always running |
| `index.html` | Frontend UI | Served by server.js |
| `Dockerfile` | Build instructions for Docker | When building image |
| `docker-compose.yml` | Local development config | When running locally |
| `k8s-todo-deployment.yaml` | Kubernetes config | When deploying to cluster |
| `setup-local.sh` | Automates local setup | First time local setup |
| `deploy-to-k8s.sh` | Automates Kubernetes deploy | Deploying to cluster |
| `verify-todo-k8s.sh` | Checks Kubernetes status | After deploying |
| `.env` | Environment variables | Always |

---

## Typical Workflow

### First Time Setup

```
1. Open PowerShell
   ↓
2. cd "G:\MCA Project\To-Do sample updated\To-Do sample"
   ↓
3. docker-compose up
   ↓
4. Open http://localhost:3001
   ↓
5. Test the app (sign up, add todos)
   ↓
6. Press Ctrl+C to stop
   ↓
7. Verify it works!
```

### Ready for Kubernetes

```
1. Make sure Kubernetes cluster is running
   ↓
2. cd "G:\MCA Project\To-Do sample updated\To-Do sample"
   ↓
3. ./deploy-to-k8s.sh
   ↓
4. ./verify-todo-k8s.sh
   ↓
5. kubectl get svc -n todo-app
   ↓
6. Open LoadBalancer IP in browser
   ↓
7. Test the app
```

---

## Ports & URLs

| Service | Local URL | Cluster URL |
|---------|-----------|------------|
| To-Do App | `http://localhost:3001` | `http://<LoadBalancer-IP>` |
| MongoDB | Cloud (Atlas) | Cloud (Atlas) |

---

## Troubleshooting Quick Fixes

### Problem: "Docker command not found"
**Solution:** Install Docker Desktop from https://www.docker.com/products/docker-desktop

### Problem: "Port 3001 already in use"
**Solution:** Edit docker-compose.yml, change `3001:3001` to `3002:3001`, then access `http://localhost:3002`

### Problem: "kubectl: command not found"
**Solution:** Install kubectl or ensure Kubernetes cluster provides kubectl

### Problem: "Cannot connect to MongoDB"
**Solution:** Check .env file has correct MONGODB_URI, or check internet connection

### Problem: App doesn't load
**Solution:** 
- Wait 5 seconds (server might still starting)
- Check logs: `docker-compose logs backend` (local) or `kubectl logs deployment/todo-backend -n todo-app` (Kubernetes)
- Verify MongoDB connection in logs

---

## Project Completion Checklist

- [ ] Install Docker Desktop
- [ ] Navigate to project folder
- [ ] Run `docker-compose up`
- [ ] Test app locally at http://localhost:3001
- [ ] Sign up and add to-do items
- [ ] Verify app works
- [ ] Stop with Ctrl+C
- [ ] (Optional) Set up Kubernetes cluster
- [ ] (Optional) Run `./deploy-to-k8s.sh`
- [ ] (Optional) Run `./verify-todo-k8s.sh`
- [ ] (Optional) Test on Kubernetes cluster

---

## Next Steps

1. **Test Locally First** (Most Important!)
   - Ensures everything works on your machine
   - Docker Compose is easier than Kubernetes
   - Tests MongoDB connection

2. **Then Deploy to Kubernetes** (When Ready)
   - Use the cluster setup from previous scripts
   - Provides production-ready setup
   - Auto-scaling and high availability

3. **Monitor & Scale**
   - Use `verify-todo-k8s.sh` to check status
   - Scale with: `kubectl scale deployment todo-backend -n todo-app --replicas=5`
   - Monitor logs: `kubectl logs -f deployment/todo-backend -n todo-app`

---

**Questions?** Check README-UPDATED.md or KUBERNETES_GUIDE.md for detailed documentation.
