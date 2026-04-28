# VIEW KUBERNETES LOGS (PowerShell)
# Simple command to view Kubernetes application logs

Write-Host "=========================================="
Write-Host "Viewing Kubernetes Application Logs"
Write-Host "=========================================="
Write-Host ""

# Check if kubectl is available
try {
    kubectl version --client > $null 2>&1
} catch {
    Write-Host "ERROR: kubectl is not installed!" -ForegroundColor Red
    exit 1
}

# Check if namespace exists
$namespace = kubectl get namespace todo-app 2>/dev/null

if (-not $namespace) {
    Write-Host "⚠️  Kubernetes application is not running!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start the application:" -ForegroundColor Cyan
    Write-Host "  .\start-kubernetes.ps1"
    Write-Host ""
    exit 1
}

# Check if pods are running
$pods = kubectl get pods -n todo-app 2>/dev/null | Select-String "Running"

if (-not $pods) {
    Write-Host "⚠️  No pods are in Running state!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Check pod status:"
    Write-Host "  kubectl get pods -n todo-app"
    Write-Host ""
    exit 1
}

Write-Host "Showing logs from Kubernetes deployment..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop viewing logs"
Write-Host ""
Write-Host "-------------------------------------------"
Write-Host ""

# Show logs in real-time
kubectl logs -f deployment/todo-backend -n todo-app

Write-Host ""
Write-Host "-------------------------------------------"
Write-Host "Logs stopped"
