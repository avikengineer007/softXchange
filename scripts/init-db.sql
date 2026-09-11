-- softXchange PostgreSQL Initialization Script
-- Creates dedicated, isolated logical databases for each service boundary.

SELECT 'CREATE DATABASE softxchange_auth'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'softxchange_auth')\gexec

SELECT 'CREATE DATABASE softxchange_listings'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'softxchange_listings')\gexec

SELECT 'CREATE DATABASE softxchange_payments'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'softxchange_payments')\gexec

SELECT 'CREATE DATABASE softxchange_scan'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'softxchange_scan')\gexec

-- Grant privileges to the service user
GRANT ALL PRIVILEGES ON DATABASE softxchange_auth TO softxchange;
GRANT ALL PRIVILEGES ON DATABASE softxchange_listings TO softxchange;
GRANT ALL PRIVILEGES ON DATABASE softxchange_payments TO softxchange;
GRANT ALL PRIVILEGES ON DATABASE softxchange_scan TO softxchange;
