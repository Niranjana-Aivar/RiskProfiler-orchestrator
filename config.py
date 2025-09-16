from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    # Execution parameters (required for AWS Batch)
    DOMAIN: Optional[str] = None
    ORGANIZATION_ID: Optional[str] = None
    SCAN_ID: Optional[str] = None
    
    # Database configurations
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "rpdatabase"
    POSTGRES_USER: str = "rpdbadmin"
    POSTGRES_PASSWORD: str = "7cP8Y0HJjg2e#~zmVvE]IBPDu9.l"
    
    # AWS configurations
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    
    # S3 configurations for AWS Batch
    S3_BUCKET: str = "riskprofiler-attack-path-automation"
    S3_TEMPLATES_KEY: str = "attack-path-rules/attack_paths_rules.json"
    
    # DynamoDB configuration
    DYNAMODB_REGION: Optional[str] = None
    DYNAMODB_ENDPOINT_URL: Optional[str] = None
    
    # LLM configurations (AWS Bedrock)
    BEDROCK_REGION: Optional[str] = None
    LLM_MODEL_ID: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    LLM_TEMPERATURE: float = 0.3
    LLM_MAX_TOKENS: int = 4000
    LLM_INFERENCE_PROFILE_ARN: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    
    # Retry and throttling configurations
    LLM_MAX_RETRY_ATTEMPTS: int = 5
    LLM_BASE_RETRY_DELAY: float = 1.0
    LLM_MAX_RETRY_DELAY: float = 30.0
    LLM_CONCURRENT_CALLS: int = 1
    LLM_CALL_DELAY: float = 2.0
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 1
    
    # Application settings
    DEFAULT_TOP_N: int = 10
    MAX_CONCURRENT_PATHS: int = 5
    LLM_CHUNK_SIZE: int = 3
    REQUEST_TIMEOUT: int = 120
    
    # Scoring weights
    LIKELIHOOD_WEIGHT: float = 0.6
    IMPACT_WEIGHT: float = 0.4
    ALPHA_WEIGHT: float = 0.6  # For risk score calculation: (likelihood * alpha + impact * (1-alpha)) * 100
    
    # Cache configuration (disabled for batch)
    CACHE_ENABLED: bool = False
    CACHE_LOG_LEVEL: str = "INFO"

    # Debug configuration
    SELECTOR_DEBUG: bool = False  # Disabled for batch to reduce log noise
    
    # Logging configuration
    LOG_LEVEL: str = "INFO"
    
    @property
    def is_aws_batch(self) -> bool:
        """Check if running in AWS Batch environment"""
        return (os.getenv('AWS_BATCH_JOB_ID') is not None or 
                self.DOMAIN is not None)
    
    @property
    def dynamodb_region_resolved(self) -> str:
        """Get resolved DynamoDB region"""
        return self.DYNAMODB_REGION or self.AWS_REGION
    
    @property
    def bedrock_region_resolved(self) -> str:
        """Get resolved Bedrock region"""
        return self.BEDROCK_REGION or self.AWS_REGION
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Ignore extra environment variables


# Global settings instance
settings = Settings() 