"""
AWS Batch configuration management using environment variables
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class BatchConfig:
    """Configuration manager for AWS Batch environment"""
    
    def __init__(self):
        """Initialize configuration from environment variables"""
        self._load_config()
        self._validate_config()
    
    def _load_config(self):
        """Load all configuration from environment variables"""
        
        # Execution Parameters
        self.domain = os.getenv('DOMAIN')
        self.organization_id = os.getenv('ORGANIZATION_ID')
        self.scan_id = os.getenv('SCAN_ID')
        
        # AWS Configuration
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.s3_bucket = os.getenv('S3_BUCKET', 'riskprofiler-attack-path-automation')
        self.s3_templates_key = os.getenv('S3_TEMPLATES_KEY', 'attack-path-rules/attack_paths_rules.json')
        
        # PostgreSQL Configuration
        self.postgres_host = os.getenv('POSTGRES_HOST')
        self.postgres_port = int(os.getenv('POSTGRES_PORT', '5432'))
        self.postgres_db = os.getenv('POSTGRES_DB')
        self.postgres_user = os.getenv('POSTGRES_USER')
        self.postgres_password = os.getenv('POSTGRES_PASSWORD')
        
        # DynamoDB Configuration
        self.dynamodb_region = os.getenv('DYNAMODB_REGION', self.aws_region)
        
        # LLM Configuration
        self.bedrock_region = os.getenv('BEDROCK_REGION', self.aws_region)
        self.llm_model_id = os.getenv('LLM_MODEL_ID', 'arn:aws:bedrock:us-east-1:519139471323:inference-profile/us.amazon.nova-pro-v1:0')
        self.alpha_weight = float(os.getenv('ALPHA_WEIGHT', '0.6'))
        
        # Batch Processing Configuration
        self.chunk_size = int(os.getenv('LLM_CHUNK_SIZE', '10'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '3'))
        self.retry_delay = int(os.getenv('RETRY_DELAY', '1'))
        
        # Logging Configuration
        self.log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        logger.info("✅ Configuration loaded from environment variables")
    
    def _validate_config(self):
        """Validate required configuration parameters"""
        required_params = {
            'DOMAIN': self.domain,
            'ORGANIZATION_ID': self.organization_id,
            'SCAN_ID': self.scan_id,
            'POSTGRES_HOST': self.postgres_host,
            'POSTGRES_DB': self.postgres_db,
            'POSTGRES_USER': self.postgres_user,
            'POSTGRES_PASSWORD': self.postgres_password,
        }
        
        missing_params = [param for param, value in required_params.items() if not value]
        
        if missing_params:
            error_msg = f"❌ Missing required environment variables: {', '.join(missing_params)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info("✅ All required configuration parameters validated")
    
    def get_postgres_dsn(self) -> str:
        """Get PostgreSQL connection DSN"""
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
    
    def get_s3_templates_path(self) -> str:
        """Get full S3 path for templates"""
        return f"s3://{self.s3_bucket}/{self.s3_templates_key}"
    
    def log_config_summary(self):
        """Log configuration summary (without sensitive data)"""
        logger.info("🔧 Batch Configuration Summary:")
        logger.info(f"   Domain: {self.domain}")
        logger.info(f"   Organization ID: {self.organization_id}")
        logger.info(f"   Scan ID: {self.scan_id}")
        logger.info(f"   AWS Region: {self.aws_region}")
        logger.info(f"   S3 Bucket: {self.s3_bucket}")
        logger.info(f"   S3 Templates: {self.s3_templates_key}")
        logger.info(f"   PostgreSQL Host: {self.postgres_host}")
        logger.info(f"   PostgreSQL Database: {self.postgres_db}")
        logger.info(f"   DynamoDB Region: {self.dynamodb_region}")
        logger.info(f"   LLM Model: {self.llm_model_id}")
        logger.info(f"   Chunk Size: {self.chunk_size}")
        logger.info(f"   Log Level: {self.log_level}")

# Global configuration instance
config = None

def get_config() -> BatchConfig:
    """Get global configuration instance"""
    global config
    if config is None:
        config = BatchConfig()
    return config

def setup_logging():
    """Setup logging configuration for batch environment"""
    config = get_config()
    
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()  # CloudWatch will capture stdout/stderr
        ]
    )
    
    # Set specific logger levels
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logger.info("✅ Logging configured for AWS Batch environment")
