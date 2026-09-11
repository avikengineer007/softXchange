@echo off
echo ===================================================
echo   Starting SoftXchange Platform Services
echo ===================================================
echo.

start "SoftXchange Auth Service (8001)" cmd /k "cd apps\auth-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Listings Service (8003)" cmd /k "cd apps\listings-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Payments Service (8004)" cmd /k "cd apps\payments-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Scan Service (8002)" cmd /k "cd apps\scan-service && ..\..\.venv\Scripts\python.exe run.py"

echo Services started in separate terminal windows.
echo.
echo ===================================================
echo   Access SoftXchange in your browser:
echo ===================================================
echo   - Landing Page:        http://localhost:8001/static/index.html
echo   - Browse Marketplace:  http://localhost:8003/static/browse-listings.html
echo   - Customer Login:      http://localhost:8001/static/login-customer.html
echo   - Seller Login:        http://localhost:8001/static/login-seller.html
echo   - Seller Dashboard:    http://localhost:8003/static/seller-listings.html
echo   - Admin Operations:    http://localhost:8001/static/admin-dashboard.html
echo.
echo   API Docs (Swagger UI):
echo   - Auth API:            http://localhost:8001/docs
echo   - Listings API:        http://localhost:8003/docs
echo   - Payments API:        http://localhost:8004/docs
echo   - Scan API:            http://localhost:8002/docs
echo ===================================================
echo.
pause
