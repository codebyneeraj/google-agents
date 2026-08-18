.PHONY: help test run demo validate deploy lint

help:
	@echo "Available commands:"
	@echo "  make gateway    - Start FastAPI Gateway Server"
	@echo "  make demo       - Run 6-step Hackathon Showcase Demo"
	@echo "  make test       - Run pytest test suite"
	@echo "  make validate   - Run Cloud Validation Suite"
	@echo "  make deploy     - Deploy to Google Cloud Run via Cloud Build"


demo:
	python demo.py

test:
	pytest -v

validate:
	python validate_cloud.py

gateway:
	uvicorn src.gateway.server:app --reload --port 8080

deploy:
	gcloud builds submit --config cloudbuild.yaml
