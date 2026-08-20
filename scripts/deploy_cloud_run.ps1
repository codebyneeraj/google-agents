# ==============================================================================
# SECURE SOC ANALYST ORCHESTRATOR - GOOGLE CLOUD RUN DEPLOYMENT SCRIPT
# Target GCP Project: primeval-melody-505912-n7
# Region: us-central1
# ==============================================================================

$PROJECT_ID = "primeval-melody-505912-n7"
$REGION = "us-central1"
$SERVICE_NAME = "soc-orchestrator"
$IMAGE_NAME = "gcr.io/$PROJECT_ID/$SERVICE_NAME"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Deploying Secure SOC Orchestrator to Google Cloud Run" -ForegroundColor Green
Write-Host "GCP Project: $PROJECT_ID | Region: $REGION" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan

# Ensure repository root is active directory
$REPO_ROOT = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path "$REPO_ROOT\cloudbuild.yaml")) {
    $REPO_ROOT = Get-Location
}
Set-Location $REPO_ROOT
Write-Host "Working Directory: $REPO_ROOT" -ForegroundColor DarkGray

# Ensure gcloud CLI is in current process PATH
$GCLOUD_PATH = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin"
if (Test-Path $GCLOUD_PATH) {
    if ($env:PATH -notlike "*$GCLOUD_PATH*") {
        $env:PATH = "$GCLOUD_PATH;$env:PATH"
    }
}

# 1. Set active GCP project
Write-Host "`n[1/5] Setting active gcloud project configuration..." -ForegroundColor Yellow
gcloud config set project $PROJECT_ID
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set GCP project. Please ensure gcloud is authenticated via 'gcloud auth login'."
    exit $LASTEXITCODE
}

# 2. Enable necessary GCP APIs
Write-Host "`n[2/5] Enabling required GCP APIs (Cloud Run, Vertex AI, Cloud Build, Artifact Registry, Logging)..." -ForegroundColor Yellow
gcloud services enable `
    run.googleapis.com `
    aiplatform.googleapis.com `
    cloudbuild.googleapis.com `
    artifactregistry.googleapis.com `
    logging.googleapis.com `
    containerregistry.googleapis.com

# 3. Submit build to Cloud Build
Write-Host "`n[3/5] Building container image and deploying to Cloud Run..." -ForegroundColor Yellow
gcloud builds submit --config="$REPO_ROOT\cloudbuild.yaml" "$REPO_ROOT"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Build failed. Check the build logs above."
    exit $LASTEXITCODE
}

# 4. Retrieve Cloud Run Service URL
Write-Host "`n[4/5] Retrieving live Cloud Run endpoint..." -ForegroundColor Yellow
$SERVICE_URL = (gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format 'value(status.url)')

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "DEPLOYMENT SUCCESSFUL!" -ForegroundColor Green
Write-Host "Live Service URL: $SERVICE_URL" -ForegroundColor Cyan
Write-Host "Agent Registry Endpoint: $SERVICE_URL/api/v1/agent/registry" -ForegroundColor Cyan
Write-Host "Health Check: $SERVICE_URL/health" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Green

# 5. Run Functionality Verification Suite against live Cloud Run URL
Write-Host "`n[5/5] Executing Live Functionality Verification Suite..." -ForegroundColor Yellow
$TEST_SCRIPT = Join-Path $REPO_ROOT "scripts\test_live_cloud.py"
$VENV_PYTHON = Join-Path $REPO_ROOT ".venv\Scripts\python.exe"

if (Test-Path $VENV_PYTHON) {
    & $VENV_PYTHON $TEST_SCRIPT --url $SERVICE_URL
} else {
    python $TEST_SCRIPT --url $SERVICE_URL
}


