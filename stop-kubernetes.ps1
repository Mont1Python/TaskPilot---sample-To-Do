# STOP KUBERNETES APPLICATION (PowerShell)
# Simple one-command shutdown

Write-Host "=========================================="
Write-Host "Stopping To-Do App from Kubernetes"
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

if ($namespace) {
    Write-Host "Deleting Kubernetes deployment..."
    
    # Kill any port-forward processes
    Get-Process kubectl -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*port-forward*3001*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    kubectl delete namespace todo-app
    
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "✓ Kubernetes Application STOPPED" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "All resources deleted:" -ForegroundColor Yellow
    Write-Host "  - Pods removed"
    Write-Host "  - Service removed"
    Write-Host "  - Deployments removed"
    Write-Host "  - Namespace removed"
    Write-Host ""
    Write-Host "To start again:" -ForegroundColor Cyan
    Write-Host "  .\start-kubernetes.ps1"
    Write-Host ""
} else {
    Write-Host "Kubernetes application is not running" -ForegroundColor Yellow
    Write-Host "Namespace 'todo-app' does not exist"
    exit 0
}
