import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

class AppConfig(BaseModel):
    app_name: str = "Secure SOC Analyst Orchestrator"
    app_id: str = "secure-soc-orchestrator"
    app_version: str = "1.0.0"
    environment: str = Field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    
    # Gemini / GEAP Settings
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", "")))
    default_model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    enterprise_mode: bool = Field(default_factory=lambda: os.getenv("GOOGLE_GENAI_USE_ENTERPRISE", "false").lower() == "true")
    
    # GCP Infrastructure & Identity
    gcp_project: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLOUD_PROJECT", "mock-enterprise-soc-project"))
    gcp_location: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"))
    google_application_credentials: str = Field(default_factory=lambda: os.getenv("GOOGLE_APPLICATION_CREDENTIALS", ""))
    
    # Memory & Session Scoping
    default_user_id: str = Field(default_factory=lambda: os.getenv("SOC_ANALYST_USER_ID", "soc_analyst_01"))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    enable_model_armor: bool = Field(default_factory=lambda: os.getenv("ENABLE_MODEL_ARMOR", "true").lower() == "true")

config = AppConfig()
