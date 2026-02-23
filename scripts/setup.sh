#!/bin/bash
set -e

# Load local environment
if [ ! -f .env ]; then
  echo "Error: .env file not found. Copy .env.example and fill in your LAB_DIR."
  exit 1
fi

source .env

# Generate kind-config.yaml from template
envsubst < cluster/kind-config.yaml.template > cluster/kind-config.yaml
echo "Generated cluster/kind-config.yaml"

# Create audit directories if they don't exist
mkdir -p "$LAB_DIR/audit-logs"
mkdir -p "$LAB_DIR/audit-config"

# Create the cluster
kind create cluster --config cluster/kind-config.yaml --name security-lab