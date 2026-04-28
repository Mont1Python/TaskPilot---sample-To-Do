# VIEW DOCKER LOGS (PowerShell)
# Simple command to view Docker application logs

Write-Host "=========================================="
Write-Host "Viewing Docker Application Logs"
Write-Host "=========================================="
Write-Host ""

# Check if docker-compose is running
$containers = docker-compose ps 2>/dev/null | Select-String "Up"

if (-not $containers) {
    Write-Host "⚠️  No Docker containers are running!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start the application:" -ForegroundColor Cyan
    Write-Host "  .\start-docker.ps1"
    Write-Host ""
    exit 1
}

Write-Host "Showing logs from Docker containers..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop viewing logs"
Write-Host ""
Write-Host "-------------------------------------------"
Write-Host ""

# Show logs in real-time
docker-compose logs -f

Write-Host ""
Write-Host "-------------------------------------------"
Write-Host "Logs stopped"
