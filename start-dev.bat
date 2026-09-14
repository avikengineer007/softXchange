@echo off
echo ===================================================
echo   Starting SoftXchange Platform Services
echo ===================================================
echo.

start "SoftXchange Unified Frontend (8000)" cmd /k "cd apps\web-unified && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Auth Service (8001)" cmd /k "cd apps\auth-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Scan Service (8002)" cmd /k "cd apps\scan-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Listings Service (8003)" cmd /k "cd apps\listings-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Payments Service (8004)" cmd /k "cd apps\payments-service && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Buyer Assist (8005)" cmd /k "cd apps\buyer-assist && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Seller Assist (8006)" cmd /k "cd apps\seller-assist && ..\..\.venv\Scripts\python.exe run.py"
start "SoftXchange Broker Service (8007)" cmd /k "cd apps\broker && ..\..\.venv\Scripts\python.exe run.py"

echo Services started in separate terminal windows.
echo.
echo ===================================================
echo   Access SoftXchange in your browser:
echo ===================================================
echo   - Unified Frontend:    http://localhost:8000/
echo   - Browse Marketplace:  http://localhost:8000/browse-listings.html
echo   - Customer Login:      http://localhost:8000/login-customer.html
echo   - Seller Login:        http://localhost:8000/login-seller.html
echo   - Seller Dashboard:    http://localhost:8000/seller-listings.html
echo   - Admin Operations:    http://localhost:8000/admin-dashboard.html
echo.
echo   API Docs (Swagger UI):
echo   - Auth API:            http://localhost:8001/docs
echo   - Scan API:            http://localhost:8002/docs
echo   - Listings API:        http://localhost:8003/docs
echo   - Payments API:        http://localhost:8004/docs
echo   - Buyer Assist API:    http://localhost:8005/docs
echo   - Seller Assist API:   http://localhost:8006/docs
echo   - Broker API:          http://localhost:8007/docs
echo ===================================================
echo.
pause
