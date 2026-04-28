# VIEW LOGS (Smart - Auto-detect) (PowerShell)
# Automatically detects if Docker or Kubernetes is running and shows logs

Write-Host "=========================================="
Write-Host "Viewing Application Logs"
Write-Host "=========================================="
Write-Host ""

# Check if Docker containers are running
$docker_running = docker-compose ps 2>/dev/null | Select-String "Up"

# Check if Kubernetes is running
$k8s_running = kubectl get namespace todo-app 2>/dev/null -ErrorAction SilentlyContinue

if ($docker_running) {
    Write-Host "✓ Docker application detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "Showing Docker logs..." -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop"
    Write-Host ""
    Write-Host "-------------------------------------------"
    Write-Host ""
    
    docker-compose logs -f
    
} elseif ($k8s_running) {
    Write-Host "✓ Kubernetes application detected" -ForegroundColor Green
    Write-Host ""
    
    # Check if pods are running
    $pods = kubectl get pods -n todo-app 2>/dev/null | Select-String "Running"
    
    if ($pods) {
        Write-Host "Showing Kubernetes logs..." -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop"
        Write-Host ""
        Write-Host "-------------------------------------------"
        Write-Host ""
        
        kubectl logs -f deployment/todo-backend -n todo-app
        
    } else {
        Write-Host "⚠️  No pods are in Running state!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Check pod status:"
        Write-Host "  kubectl get pods -n todo-app"
    }
    
} else {
    Write-Host "⚠️  No application is running!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start the application:" -ForegroundColor Cyan
    Write-Host "  Docker:      .\start-docker.ps1"
    Write-Host "  Kubernetes:  .\start-kubernetes.ps1"
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "-------------------------------------------"
Write-Host "Logs stopped"
