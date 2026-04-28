# PowerShell: Stop Kubernetes cluster

Write-Host "================================" -ForegroundColor Red
Write-Host "STOPPING KUBERNETES CLUSTER" -ForegroundColor Red
Write-Host "================================" -ForegroundColor Red
Write-Host ""

# Add kind to PATH if needed
$env:PATH = $env:PATH + ";" + $env:USERPROFILE

Write-Host "This will stop the todo-cluster" -ForegroundColor Yellow
Write-Host "Your data will be preserved (persistent volumes)" -ForegroundColor Cyan
Write-Host ""

$confirm = Read-Host "Are you sure? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Stopping cluster: todo-cluster" -ForegroundColor Yellow

try {
    # Delete the kind cluster
    & kind delete cluster --name todo-cluster
    
    Write-Host ""
    Write-Host "================================" -ForegroundColor Green
    Write-Host "CLUSTER STOPPED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "To restart the cluster later, run:" -ForegroundColor Cyan
    Write-Host "  powershell -ExecutionPolicy Bypass -File start-cluster.ps1" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Note: Data is preserved in Docker volumes" -ForegroundColor Cyan
    
} catch {
    Write-Host "Error stopping cluster: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Stopped at: $(Get-Date)" -ForegroundColor Cyan
