#!/bin/bash
# Local Python setup for PhishHunter; DB migration/bootstrap are explicit steps.

set -e

echo "=== PhishHunter Project Setup ==="

# Check Python version
python3 -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'"
echo "Python version OK"

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env — configure DATABASE_URL/JWT_SECRET; external API keys are optional"
fi

echo "Python setup complete. Follow docs/runbook.md for PostgreSQL migration, admin bootstrap and frontend."
