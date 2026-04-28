Write-Host 'Kubernetes Cluster Dashboard' -ForegroundColor Cyan
Write-Host 'Press Ctrl+C to exit' -ForegroundColor Yellow
Write-Host ''

while ($true) {
    Clear-Host
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host '        KUBERNETES CLUSTER: todo-cluster' -ForegroundColor Cyan
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host ''
    
    try {
        $clusterTest = kubectl cluster-info 2>$null
        Write-Host 'Overall Status: RUNNING' -ForegroundColor Green
    } catch {
        Write-Host 'Overall Status: NOT RUNNING' -ForegroundColor Red
        Start-Sleep -Seconds 5
        continue
    }
    
    Write-Host ''
    
    Write-Host '--- NODES ---' -ForegroundColor Cyan
    $nodes = kubectl get nodes -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type --no-headers 2>$null
    if ($nodes) {
        $nodes | ForEach-Object { Write-Host  [OK] $_ -ForegroundColor Green }
    }
    Write-Host ''
    
    Write-Host '--- PODS (todo-app namespace) ---' -ForegroundColor Cyan
    $pods = kubectl get pods -n todo-app -o custom-columns=NAME:.metadata.name,STATUS:.status.phase --no-headers 2>$null
    if ($pods) {
        $pods | ForEach-Object { 
            if ($_ -match 'Running') { 
                Write-Host  [RUNNING] $_ -ForegroundColor Green 
            } elseif ($_ -match 'Pending') {
                Write-Host  [PENDING] $_ -ForegroundColor Yellow
            } else {
                Write-Host  [ERROR] $_ -ForegroundColor Red
            }
        }
    }
    Write-Host ''
    
    Write-Host '--- SERVICES ---' -ForegroundColor Cyan
    $svcs = kubectl get svc -n todo-app -o custom-columns=NAME:.metadata.name,TYPE:.spec.type --no-headers 2>$null
    if ($svcs) {
        $svcs | ForEach-Object { Write-Host  $_ -ForegroundColor White }
    }
    Write-Host ''
    
    Write-Host '--- ACCESS INFO ---' -ForegroundColor Cyan
    Write-Host '  Web App: http://localhost:8080' -ForegroundColor Cyan
    Write-Host '  Database: mongodb-service:27017' -ForegroundColor Cyan
    Write-Host ''
    
    Write-Host '--- QUICK ACTIONS ---' -ForegroundColor Yellow
    Write-Host '  Pause:  powershell -ExecutionPolicy Bypass -File pause-cluster.ps1' -ForegroundColor Yellow
    Write-Host '  Stop:   powershell -ExecutionPolicy Bypass -File stop-cluster.ps1' -ForegroundColor Yellow
    Write-Host ''
    
    Write-Host 'Refreshing in 5 seconds (Ctrl+C to exit)' -ForegroundColor Gray
    Start-Sleep -Seconds 5
}
