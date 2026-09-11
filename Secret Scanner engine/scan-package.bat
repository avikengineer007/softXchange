@echo off
python -m static_analysis.cli %* --with-secrets-scan
