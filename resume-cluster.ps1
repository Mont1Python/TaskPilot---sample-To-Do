# PowerShell: Resume paused cluster

Write-Host "================================" -ForegroundColor Green
Write-Host "RESUMING KUBERNETES CLUSTER" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""

Write-Host "Resuming paused containers..." -ForegroundColor Yellow

try {
    # Get all paused Docker containers for the kind cluster
    $containers = docker ps -a --filter "status=paused" --filter "name=todo-cluster" --format "{{.ID}} {{.Names}}"
    
    if (-not $containers) {
        Write-Host "No paused containers found" -ForegroundColor Yellow
        exit 0
    }
    
    foreach ($line in $containers) {
        if ($line) {
            $id = $line.Split()[0]
            $name = $line.Split()[1]
            Write-Host "  Resuming: $name" -ForegroundColor Cyan
            docker unpause $id
        }
    }
    
    Write-Host ""
    Write-Host "Waiting for cluster to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Check cluster status
    $clusterStatus = kubectl cluster-info 2>$null
    if ($clusterStatus) {
        Write-Host ""
        Write-Host "================================" -ForegroundColor Green
        Write-Host "CLUSTER RESUMED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "================================" -ForegroundColor Green
        Write-Host ""
        
        kubectl get nodes
        Write-Host ""
        kubectl get pods -n todo-app
        Write-Host ""
        
        Write-Host "Start port-forward to access the app:" -ForegroundColor Cyan
        Write-Host "  kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error resuming cluster: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Resumed at: $(Get-Date)" -ForegroundColor Cyan
