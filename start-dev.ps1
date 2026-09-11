# SoftXchange Platform Services Launcher

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Starting SoftXchange Platform Services" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build 3D assets (fast, only copies if changed)
Write-Host " [3D] Building and distributing 3D assets..." -ForegroundColor Magenta
& npm run 3d:build 2>&1 | Out-Null
Write-Host " [3D] Assets ready." -ForegroundColor Green
Write-Host ""

# Step 2: Launch services in separate windows
$py = "$PSScriptRoot\.venv\Scripts\python.exe"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Unified Web Frontend (8000)'; Write-Host 'Starting Unified Frontend on 8000...' -ForegroundColor Cyan; cd '$PSScriptRoot\apps\web-unified'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Auth Service (8001)'; Write-Host 'Starting Auth Service on 8001...' -ForegroundColor Green; cd '$PSScriptRoot\apps\auth-service'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Listings Service (8003)'; Write-Host 'Starting Listings Service on 8003...' -ForegroundColor Green; cd '$PSScriptRoot\apps\listings-service'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Payments Service (8004)'; Write-Host 'Starting Payments Service on 8004...' -ForegroundColor Green; cd '$PSScriptRoot\apps\payments-service'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Scan Service (8002)'; Write-Host 'Starting Scan Service on 8002...' -ForegroundColor Green; cd '$PSScriptRoot\apps\scan-service'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Buyer Assist Service (8005)'; Write-Host 'Starting Buyer Assist on 8005...' -ForegroundColor Magenta; cd '$PSScriptRoot\apps\buyer-assist'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Seller Assist Service (8006)'; Write-Host 'Starting Seller Assist on 8006...' -ForegroundColor Magenta; cd '$PSScriptRoot\apps\seller-assist'; & '$py' run.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.ui.RawUI.WindowTitle = 'softXchange: Broker Service (8007)'; Write-Host 'Starting Broker Service on 8007...' -ForegroundColor Magenta; cd '$PSScriptRoot\apps\broker'; & '$py' run.py"

Write-Host "Services launched in separate PowerShell windows." -ForegroundColor Green
Write-Host ""
Write-Host "===================================================" -ForegroundColor Yellow
Write-Host "  Access SoftXchange in your browser:" -ForegroundColor Yellow
Write-Host "===================================================" -ForegroundColor Yellow
Write-Host "  - Unified Frontend:      http://localhost:8000/"
Write-Host "  - Browse Marketplace:    http://localhost:8000/browse-listings.html"
Write-Host "  - Customer Login:        http://localhost:8000/login-customer.html"
Write-Host "  - Seller Login:          http://localhost:8000/login-seller.html"
Write-Host "  - Seller Package Mgr:    http://localhost:8000/seller-listings.html"
Write-Host "  - Admin Operations:      http://localhost:8000/admin-dashboard.html"
Write-Host ""
Write-Host "  API Docs (Swagger UI - Backend & ML APIs):" -ForegroundColor Cyan
Write-Host "  - Auth API:              http://localhost:8001/docs"
Write-Host "  - Scan API:              http://localhost:8002/docs"
Write-Host "  - Listings API:          http://localhost:8003/docs"
Write-Host "  - Payments API:          http://localhost:8004/docs"
Write-Host "  - Buyer Assist API:      http://localhost:8005/docs"
Write-Host "  - Seller Assist API:     http://localhost:8006/docs"
Write-Host "  - Broker API:            http://localhost:8007/docs"
Write-Host "===================================================" -ForegroundColor Yellow
