# PowerShell: Start Kubernetes cluster

Write-Host "================================" -ForegroundColor Green
Write-Host "STARTING KUBERNETES CLUSTER" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""

# Add kind to PATH if needed
$env:PATH = $env:PATH + ";" + $env:USERPROFILE

Write-Host "Starting cluster: todo-cluster" -ForegroundColor Yellow

try {
    # Start the cluster
    $output = & kind export kubeconfig --name todo-cluster 2>&1
    
    Write-Host "Waiting for cluster to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Check if running
    $clusterStatus = kubectl cluster-info 2>$null
    if ($clusterStatus) {
        Write-Host ""
        Write-Host "================================" -ForegroundColor Green
        Write-Host "CLUSTER STARTED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "================================" -ForegroundColor Green
        Write-Host ""
        
        kubectl cluster-info
        Write-Host ""
        
        Write-Host "Nodes:" -ForegroundColor Cyan
        kubectl get nodes
        Write-Host ""
        
        Write-Host "Pods (todo-app namespace):" -ForegroundColor Cyan
        kubectl get pods -n todo-app
        Write-Host ""
        
        Write-Host "Access your app at: http://localhost:8080" -ForegroundColor Green
        Write-Host "Run this to start port-forward:" -ForegroundColor Cyan
        Write-Host "  kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80" -ForegroundColor Yellow
        
    } else {
        Write-Host "Cluster may not be ready yet. Retrying..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        kubectl cluster-info
    }
    
} catch {
    Write-Host "Error starting cluster: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Started at: $(Get-Date)" -ForegroundColor Cyan
