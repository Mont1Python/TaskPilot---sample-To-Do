# Test login with existing credentials

$API = "http://localhost:8080"

Write-Host "Testing login with existing account..." -ForegroundColor Cyan

# Login
$loginBody = @{
    email = "test@example.com"
    password = "password123"
} | ConvertTo-Json

Write-Host "Sending login request to: $API/login" -ForegroundColor Yellow
Write-Host "Email: test@example.com" -ForegroundColor Yellow
Write-Host "Password: password123" -ForegroundColor Yellow
Write-Host ""

try {
    $loginResponse = Invoke-WebRequest -Uri "$API/login" `
        -Method POST `
        -Headers @{"Content-Type" = "application/json"} `
        -Body $loginBody -UseBasicParsing
    
    $loginData = $loginResponse.Content | ConvertFrom-Json
    Write-Host "Login successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Response:" -ForegroundColor Cyan
    Write-Host ($loginData | ConvertTo-Json -Depth 5)
    
} catch {
    $errorResponse = $_.Exception.Response
    if ($errorResponse) {
        $reader = New-Object System.IO.StreamReader($errorResponse.GetResponseStream())
        $errorContent = $reader.ReadToEnd()
        Write-Host "Login failed!" -ForegroundColor Red
        Write-Host "Status Code: $($errorResponse.StatusCode)" -ForegroundColor Yellow
        Write-Host "Error Response:" -ForegroundColor Yellow
        Write-Host $errorContent
    } else {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}
