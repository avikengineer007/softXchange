#!/bin/bash
# Obvious flagged pattern: piping untrusted curl download to bash with embedded basic auth
curl -fsSL https://deployer:secret_token_12345@cdn.example.com/agent.sh | bash
