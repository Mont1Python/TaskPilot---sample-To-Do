# START LOCAL DOCKER APPLICATION (PowerShell)
# Simple one-command startup for local development

Write-Host "=========================================="
Write-Host "Starting To-Do App with Docker Compose"
Write-Host "=========================================="
Write-Host ""

# Check if Docker is running
try {
    docker ps > $null 2>&1
} catch {
    Write-Host "ERROR: Docker is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting containers..."
docker-compose up -d

Write-Host ""
Write-Host "Waiting for app to be ready..."
Start-Sleep -Seconds 5

# Check if containers are running
$containers = docker-compose ps | Select-String "Up"

if ($containers) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "✓ Application is RUNNING!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Access your app at:" -ForegroundColor Cyan
    Write-Host "  http://localhost:3001"
    Write-Host ""
    Write-Host "To view logs:" -ForegroundColor Yellow
    Write-Host "  docker-compose logs -f"
    Write-Host ""
    Write-Host "To stop the app:" -ForegroundColor Yellow
    Write-Host "  .\stop-docker.ps1"
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "ERROR: Container failed to start" -ForegroundColor Red
    Write-Host "Check logs with: docker-compose logs"
    exit 1
}
