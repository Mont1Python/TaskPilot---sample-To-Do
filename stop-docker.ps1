# STOP LOCAL DOCKER APPLICATION (PowerShell)
# Simple one-command shutdown

Write-Host "=========================================="
Write-Host "Stopping To-Do App"
Write-Host "=========================================="
Write-Host ""

# Check if containers are running
$containers = docker-compose ps | Select-String "Up"

if ($containers) {
    Write-Host "Stopping containers..."
    docker-compose down
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "✓ Application STOPPED" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start again:" -ForegroundColor Cyan
    Write-Host "  .\start-docker.ps1"
    Write-Host ""
} else {
    Write-Host "No containers are running" -ForegroundColor Yellow
    exit 0
}
