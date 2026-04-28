# START KUBERNETES APPLICATION (PowerShell)
# Simple one-command startup for Kubernetes deployment

Write-Host "=========================================="
Write-Host "Starting To-Do App on Kubernetes"
Write-Host "=========================================="
Write-Host ""

# Check if kubectl is available
try {
    kubectl cluster-info > $null 2>&1
} catch {
    Write-Host "ERROR: kubectl is not available or cluster not running!" -ForegroundColor Red
    exit 1
}

Write-Host "Cluster OK"
Write-Host "Building Docker image (this may take 1-2 minutes)..."

# Build image
docker build -t todo-app:latest . | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Image built successfully"
Write-Host ""
Write-Host "Deploying to Kubernetes..."
kubectl apply -f k8s-todo-deployment.yaml | Out-Null

Write-Host "Waiting for pods to start..."
Start-Sleep -Seconds 3

# Wait for pods to be running
$maxWait = 30
$waited = 0
while ($waited -lt $maxWait) {
    $running = kubectl get pods -n todo-app 2>/dev/null | Select-String "Running" | Measure-Object | Select-Object -ExpandProperty Count
    
    if ($running -eq 2) {
        break
    }
    
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 1
    $waited++
}

Write-Host ""
Write-Host ""

# Check if pods are running
$pods = kubectl get pods -n todo-app 2>/dev/null | Select-String "Running"

if ($pods) {
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "✓ Kubernetes Application is RUNNING!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    
    # Setup port forward in background
    Write-Host "Setting up port forwarding..."
    
    # Kill any existing port-forward on port 3001
    Get-Process kubectl -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*port-forward*3001*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Start-Process -NoNewWindow -WindowStyle Hidden -FilePath "kubectl" -ArgumentList "port-forward", "svc/todo-backend-service", "3001:80", "-n", "todo-app"
    
    Start-Sleep -Seconds 2
    
    Write-Host ""
    Write-Host "Access your app at:" -ForegroundColor Cyan
    Write-Host "  http://localhost:3001"
    Write-Host ""
    Write-Host "Kubernetes Details:" -ForegroundColor Yellow
    Write-Host "  Pods: 2 running"
    Write-Host "  Namespace: todo-app"
    Write-Host "  Auto-scaling: Enabled (2-5 pods)"
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor Yellow
    Write-Host "  View logs:"
    Write-Host "    kubectl logs -f deployment/todo-backend -n todo-app"
    Write-Host ""
    Write-Host "  Check pods:"
    Write-Host "    kubectl get pods -n todo-app"
    Write-Host ""
    Write-Host "  Check all resources:"
    Write-Host "    kubectl get all -n todo-app"
    Write-Host ""
    Write-Host "To stop the app:" -ForegroundColor Cyan
    Write-Host "  .\stop-kubernetes.ps1"
    Write-Host ""
    
} else {
    Write-Host "ERROR: Pods failed to start" -ForegroundColor Red
    Write-Host "Check with: kubectl get pods -n todo-app"
    Write-Host "View logs: kubectl logs deployment/todo-backend -n todo-app"
    exit 1
}
