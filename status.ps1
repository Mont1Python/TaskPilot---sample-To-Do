# CHECK APPLICATION STATUS (PowerShell)
# Simple command to check if application is running

Write-Host "=========================================="
Write-Host "Checking Application Status"
Write-Host "=========================================="
Write-Host ""

$docker_running = $false
$k8s_running = $false

# Check Docker status
$docker_containers = docker-compose ps 2>/dev/null | Select-String "Up"
if ($docker_containers) {
    $docker_running = $true
}

# Check Kubernetes status
$k8s_ns = kubectl get namespace todo-app 2>/dev/null -ErrorAction SilentlyContinue
if ($k8s_ns) {
    $k8s_running = $true
}

# Display results
if ($docker_running) {
    Write-Host "🐳 DOCKER APPLICATION" -ForegroundColor Cyan
    Write-Host "-------------------------------------------" -ForegroundColor Cyan
    Write-Host "✓ Status: RUNNING" -ForegroundColor Green
    Write-Host ""
    
    # Show container status
    docker-compose ps | Format-Table
    
    Write-Host "Access: http://localhost:3001" -ForegroundColor Green
    Write-Host ""
}

if ($k8s_running) {
    Write-Host "☸️  KUBERNETES APPLICATION" -ForegroundColor Cyan
    Write-Host "-------------------------------------------" -ForegroundColor Cyan
    Write-Host "✓ Status: RUNNING" -ForegroundColor Green
    Write-Host ""
    
    # Show pod status
    Write-Host "Pods:"
    kubectl get pods -n todo-app
    
    Write-Host ""
    
    # Show service status
    Write-Host "Service:"
    kubectl get svc -n todo-app
    
    Write-Host ""
    Write-Host "Access: http://localhost:3001" -ForegroundColor Green
    Write-Host ""
}

if (-not $docker_running -and -not $k8s_running) {
    Write-Host "⚠️  NO APPLICATION RUNNING" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start application:" -ForegroundColor Cyan
    Write-Host "  Docker:      .\start-docker.ps1"
    Write-Host "  Kubernetes:  .\start-kubernetes.ps1"
    Write-Host ""
    exit 1
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "✓ Status check complete" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Show next steps
Write-Host "Useful Commands:" -ForegroundColor Yellow
Write-Host "  View logs:       .\logs.ps1"
Write-Host "  Stop application (Docker):      .\stop-docker.ps1"
Write-Host "  Stop application (Kubernetes):  .\stop-kubernetes.ps1"
Write-Host ""
