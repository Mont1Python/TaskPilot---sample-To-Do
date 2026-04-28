# PowerShell: Pause/suspend cluster (save resources without deleting)

Write-Host "================================" -ForegroundColor Yellow
Write-Host "PAUSING KUBERNETES CLUSTER" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "This will pause all containers while keeping data intact" -ForegroundColor Cyan
Write-Host "Resources used: Minimal" -ForegroundColor Green
Write-Host ""

$confirm = Read-Host "Pause cluster? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

try {
    # Get all Docker containers for the kind cluster
    Write-Host "Finding kind cluster containers..." -ForegroundColor Yellow
    $containers = docker ps -a --filter "label=io.x-k8s.kind.cluster=todo-cluster" --format "{{.ID}} {{.Names}}"
    
    if (-not $containers) {
        Write-Host "No containers found for cluster. Trying alternative method..." -ForegroundColor Yellow
        $containers = docker ps -a --filter "name=todo-cluster" --format "{{.ID}} {{.Names}}"
    }
    
    if (-not $containers) {
        Write-Host "Error: Could not find cluster containers" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Pausing containers..." -ForegroundColor Yellow
    foreach ($line in $containers) {
        if ($line) {
            $id = $line.Split()[0]
            $name = $line.Split()[1]
            Write-Host "  Pausing: $name" -ForegroundColor Cyan
            docker pause $id
        }
    }
    
    Write-Host ""
    Write-Host "================================" -ForegroundColor Green
    Write-Host "CLUSTER PAUSED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "To resume the cluster, run:" -ForegroundColor Cyan
    Write-Host "  powershell -ExecutionPolicy Bypass -File resume-cluster.ps1" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Storage used: Minimal (paused containers)" -ForegroundColor Green
    
} catch {
    Write-Host "Error pausing cluster: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Paused at: $(Get-Date)" -ForegroundColor Cyan
