# PowerShell: Export cluster status report

param(
    [string]$OutputFile = "cluster-status-report.txt"
)

Write-Host "Generating cluster status report..." -ForegroundColor Yellow
Write-Host "Output file: $OutputFile" -ForegroundColor Cyan

$report = @()

$report += "╔════════════════════════════════════════════════════════════════╗"
$report += "║         KUBERNETES CLUSTER STATUS REPORT                       ║"
$report += "╚════════════════════════════════════════════════════════════════╝"
$report += ""
$report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Cluster: todo-cluster"
$report += ""

# Check cluster status
try {
    $clusterInfo = kubectl cluster-info 2>$null
    $report += "Status: ✅ RUNNING"
} catch {
    $report += "Status: ❌ NOT RUNNING"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "NODES"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$nodes = kubectl get nodes -o wide 2>$null
if ($nodes) {
    $report += $nodes | Out-String
} else {
    $report += "No nodes available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "PODS (todo-app namespace)"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$pods = kubectl get pods -n todo-app -o wide 2>$null
if ($pods) {
    $report += $pods | Out-String
} else {
    $report += "No pods available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "SERVICES"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$svcs = kubectl get svc -n todo-app 2>$null
if ($svcs) {
    $report += $svcs | Out-String
} else {
    $report += "No services available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "PERSISTENT VOLUMES"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$pvc = kubectl get pvc -n todo-app 2>$null
if ($pvc) {
    $report += $pvc | Out-String
} else {
    $report += "No PVCs available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "DEPLOYMENTS"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$deploy = kubectl get deployments -n todo-app 2>$null
if ($deploy) {
    $report += $deploy | Out-String
} else {
    $report += "No deployments available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "STATEFULSETS"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$sts = kubectl get statefulsets -n todo-app 2>$null
if ($sts) {
    $report += $sts | Out-String
} else {
    $report += "No StatefulSets available"
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "CLUSTER INFO"
$report += "════════════════════════════════════════════════════════════════"
$report += ""

$clusterDetails = kubectl cluster-info 2>$null
if ($clusterDetails) {
    $report += $clusterDetails | Out-String
}

$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "ACCESS INFORMATION"
$report += "════════════════════════════════════════════════════════════════"
$report += ""
$report += "Web Application: http://localhost:8080"
$report += "Database: mongodb-service:27017 (internal)"
$report += "API Endpoint: http://localhost:8080"
$report += ""
$report += "Port-forward command:"
$report += "  kubectl port-forward -n todo-app svc/todo-frontend-lb 8080:80"
$report += ""
$report += "════════════════════════════════════════════════════════════════"
$report += "MANAGEMENT COMMANDS"
$report += "════════════════════════════════════════════════════════════════"
$report += ""
$report += "Check status:"
$report += "  powershell -ExecutionPolicy Bypass -File check-cluster-status.ps1"
$report += ""
$report += "Pause cluster:"
$report += "  powershell -ExecutionPolicy Bypass -File pause-cluster.ps1"
$report += ""
$report += "Resume cluster:"
$report += "  powershell -ExecutionPolicy Bypass -File resume-cluster.ps1"
$report += ""
$report += "Stop cluster:"
$report += "  powershell -ExecutionPolicy Bypass -File stop-cluster.ps1"
$report += ""

# Write to file
$report -join [Environment]::NewLine | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "✅ Report generated: $OutputFile" -ForegroundColor Green
Write-Host ""
Write-Host "Report contents:" -ForegroundColor Cyan
Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Get-Content $OutputFile
Write-Host ""
Write-Host "You can now share this file with others to show cluster status." -ForegroundColor Green
