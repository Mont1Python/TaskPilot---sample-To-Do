# PowerShell script to check Kubernetes cluster status

function Show-ClusterStatus {
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "KUBERNETES CLUSTER STATUS" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""

    # Check if cluster is running
    try {
        $clusterInfo = kubectl cluster-info 2>$null
        Write-Host "Status: RUNNING" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Host "Status: NOT RUNNING" -ForegroundColor Red
        return
    }

    # Cluster info
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "CLUSTER INFORMATION" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl cluster-info
    Write-Host ""

    # Nodes status
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "NODES STATUS" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl get nodes -o wide
    Write-Host ""

    # Node details
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "NODE DETAILS" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl describe nodes
    Write-Host ""

    # Pods status
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "POD STATUS (todo-app namespace)" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl get pods -n todo-app -o wide
    Write-Host ""

    # Services
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "SERVICES" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl get svc -n todo-app
    Write-Host ""

    # Storage
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "PERSISTENT VOLUMES" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    kubectl get pvc -n todo-app
    Write-Host ""

    Write-Host "Status Report Generated: $(Get-Date)" -ForegroundColor Yellow
}

Show-ClusterStatus
