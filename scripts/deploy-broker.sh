#!/usr/bin/env bash
# ============================================================
#  1-Click Private Broker Deployment Script
# ============================================================
set -e

echo "🚀 Deploying iPingYou Central Broker Server..."

if command -v docker-compose &> /dev/null; then
  docker-compose up -d --build
elif command -v docker &> /dev/null; then
  docker compose up -d --build
else
  echo "❌ Error: Docker is required to run self-hosted broker."
  exit 1
fi

echo "✅ Broker deployed successfully! Listening on http://localhost:3000"
echo "💡 Override clients & hosts to use your broker:"
echo "   npx ipingyou host --broker http://your-domain.com:3000"
