#!/usr/bin/env bash
set -e

PROJECT_ID="primeval-melody-505912-n7"
REGION="us-central1"
SERVICE_NAME="soc-orchestrator"

echo "========================================================"
echo "Deploying Secure SOC Orchestrator to Google Cloud Run"
echo "GCP Project: $PROJECT_ID | Region: $REGION"
echo "========================================================"

# 1. Set active GCP project
echo "[1/4] Setting active gcloud project..."
gcloud config set project "$PROJECT_ID"

# 2. Enable required GCP APIs
echo "[2/4] Enabling required GCP APIs..."
gcloud services enable \
    run.googleapis.com \
    aiplatform.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    logging.googleapis.com

# 3. Submit build to Cloud Build
echo "[3/4] Building and deploying via Cloud Build..."
gcloud builds submit --config=cloudbuild.yaml .

# 4. Output service URL
echo "[4/4] Retrieving live service URL..."
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --platform managed --region "$REGION" --format 'value(status.url)')

echo "========================================================"
echo "DEPLOYMENT COMPLETE!"
echo "Service URL: $SERVICE_URL"
echo "Health Check: $SERVICE_URL/health"
echo "Agent Registry: $SERVICE_URL/api/v1/agent/registry"
echo "========================================================"
