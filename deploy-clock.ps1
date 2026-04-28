# DEPLOY LIVE CLOCK DASHBOARD (PowerShell)
# Simple one-command deployment of the live clock

Write-Host "=========================================="
Write-Host "Deploying Live Clock Dashboard"
Write-Host "=========================================="
Write-Host ""

# Check if kubectl is available
try {
    kubectl cluster-info > $null 2>&1
} catch {
    Write-Host "ERROR: kubectl is not available!" -ForegroundColor Red
    exit 1
}

# Check if Ansible is installed
if (-not (Get-Command ansible -ErrorAction SilentlyContinue)) {
    Write-Host "Ansible not found. Installing with pip..." -ForegroundColor Yellow
    pip install ansible-core kubernetes
    Write-Host ""
}

Write-Host "Checking cluster..." -ForegroundColor Cyan
kubectl cluster-info > $null

Write-Host "Deploying clock dashboard with Ansible..." -ForegroundColor Green
Write-Host ""

# Run Ansible playbook
ansible-playbook deploy-clock.yml -v

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "✓ Clock Dashboard Deployed Successfully!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Access your clock at:" -ForegroundColor Cyan
    
    # Get service info
    $service_info = kubectl get svc -n clock-dashboard live-clock-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null
    
    if ($service_info) {
        Write-Host "  http://$service_info" -ForegroundColor Green
    } else {
        Write-Host "  Get LoadBalancer IP with: kubectl get svc -n clock-dashboard" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Useful Commands:" -ForegroundColor Yellow
    Write-Host "  View pods:     kubectl get pods -n clock-dashboard"
    Write-Host "  View service:  kubectl get svc -n clock-dashboard"
    Write-Host "  View logs:     kubectl logs -f deployment/live-clock -n clock-dashboard"
    Write-Host ""
    
} else {
    Write-Host ""
    Write-Host "ERROR: Deployment failed!" -ForegroundColor Red
    exit 1
}
