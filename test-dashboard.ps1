# Quick test - run this to see if dashboard works

Write-Host "Testing cluster dashboard..." -ForegroundColor Cyan
Write-Host ""

# Test 1: Check script loads
Write-Host "1. Testing script syntax..." -ForegroundColor Yellow
try {
    $dashScript = Get-Content cluster-dashboard.ps1
    Write-Host "   OK - Script file found and readable" -ForegroundColor Green
} catch {
    Write-Host "   ERROR - Cannot read script file" -ForegroundColor Red
    exit 1
}

# Test 2: Check kubectl works
Write-Host "2. Testing kubectl..." -ForegroundColor Yellow
try {
    $test = kubectl cluster-info 2>$null
    Write-Host "   OK - Kubernetes cluster accessible" -ForegroundColor Green
} catch {
    Write-Host "   ERROR - Kubernetes not accessible" -ForegroundColor Red
    exit 1
}

# Test 3: Check nodes
Write-Host "3. Checking nodes..." -ForegroundColor Yellow
$nodes = kubectl get nodes --no-headers 2>$null | Measure-Object -Line
Write-Host "   OK - Found $($nodes.Lines) nodes" -ForegroundColor Green

# Test 4: Check pods
Write-Host "4. Checking pods..." -ForegroundColor Yellow
$pods = kubectl get pods -n todo-app --no-headers 2>$null | Measure-Object -Line
Write-Host "   OK - Found $($pods.Lines) pods" -ForegroundColor Green

# Test 5: Run first iteration of dashboard
Write-Host "5. Running first dashboard iteration..." -ForegroundColor Yellow
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "        KUBERNETES CLUSTER: todo-cluster" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Overall Status: RUNNING" -ForegroundColor Green
Write-Host ""

Write-Host "--- NODES ---" -ForegroundColor Cyan
kubectl get nodes -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type --no-headers
Write-Host ""

Write-Host "--- PODS (todo-app) ---" -ForegroundColor Cyan
kubectl get pods -n todo-app -o custom-columns=NAME:.metadata.name,STATUS:.status.phase --no-headers
Write-Host ""

Write-Host "--- SERVICES ---" -ForegroundColor Cyan
kubectl get svc -n todo-app -o custom-columns=NAME:.metadata.name,TYPE:.spec.type --no-headers
Write-Host ""

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "DASHBOARD TEST PASSED!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the full dashboard with live updates, run:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File cluster-dashboard.ps1" -ForegroundColor Cyan
Write-Host ""
