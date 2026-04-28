# Quick test script for to-do app signup and login

$API = "http://localhost:8080"

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Creating new user account..." -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Signup
$signupBody = @{
    name = "Test User"
    email = "test@example.com"
    password = "password123"
} | ConvertTo-Json

try {
    $signupResponse = Invoke-WebRequest -Uri "$API/signup" `
        -Method POST `
        -Headers @{"Content-Type" = "application/json"} `
        -Body $signupBody -UseBasicParsing
    
    $signupData = $signupResponse.Content | ConvertFrom-Json
    Write-Host "Signup Response:" -ForegroundColor Green
    Write-Host ($signupData | ConvertTo-Json -Depth 5)
    
    $token = $signupData.token
    
    if (-not $token) {
        Write-Host "Signup failed - no token returned" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "Signup successful!" -ForegroundColor Green
    Write-Host "Token: $token" -ForegroundColor Cyan
    
} catch {
    Write-Host "Signup error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Logging in with same credentials..." -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Login
$loginBody = @{
    email = "test@example.com"
    password = "password123"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-WebRequest -Uri "$API/login" `
        -Method POST `
        -Headers @{"Content-Type" = "application/json"} `
        -Body $loginBody -UseBasicParsing
    
    $loginData = $loginResponse.Content | ConvertFrom-Json
    Write-Host "Login Response:" -ForegroundColor Green
    Write-Host ($loginData | ConvertTo-Json -Depth 5)
    
    $loginToken = $loginData.token
    
    if (-not $loginToken) {
        Write-Host "Login failed - no token returned" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "Login successful!" -ForegroundColor Green
    Write-Host "Token: $loginToken" -ForegroundColor Cyan
    
} catch {
    Write-Host "Login error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Creating a to-do task..." -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Create todo
$todoBody = @{
    text = "My First Task on Kubernetes"
    list = "My Day"
    subText = "This is running on Kubernetes!"
    type = "todo"
} | ConvertTo-Json

try {
    $todoResponse = Invoke-WebRequest -Uri "$API/todos" `
        -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $loginToken"
        } `
        -Body $todoBody -UseBasicParsing
    
    $todoData = $todoResponse.Content | ConvertFrom-Json
    Write-Host "Create Todo Response:" -ForegroundColor Green
    Write-Host ($todoData | ConvertTo-Json -Depth 5)
    
} catch {
    Write-Host "Create Todo error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "All tests passed!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Your Account Details:" -ForegroundColor Cyan
Write-Host "  Email: test@example.com" -ForegroundColor White
Write-Host "  Password: password123" -ForegroundColor White
Write-Host "  Name: Test User" -ForegroundColor White
Write-Host ""
Write-Host "Access the app at: http://localhost:8080" -ForegroundColor Cyan
