"""
S3 utilities for AWS Batch deployment with archive management
"""
import boto3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError
import time
import os

logger = logging.getLogger(__name__)

class S3Manager:
    """Manages S3 operations for attack path results with archive functionality"""
    
    def __init__(self, bucket_name: str, region: str = None):
        """
        Initialize S3 manager
        
        Args:
            bucket_name: S3 bucket name
            region: AWS region (optional, uses default if not specified)
        """
        self.bucket_name = bucket_name
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        
        try:
            self.s3_client = boto3.client('s3', region_name=self.region)
            logger.info(f"✅ S3 client initialized for bucket: {bucket_name}")
        except NoCredentialsError:
            logger.error("❌ AWS credentials not found")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to initialize S3 client: {e}")
            raise
    
    def download_attack_path_templates(self, s3_key: str) -> Dict[str, Any]:
        """
        Download attack path templates from S3
        
        Args:
            s3_key: S3 key for the templates file
            
        Returns:
            Dict containing the templates data
        """
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                logger.info(f"📥 Downloading templates from s3://{self.bucket_name}/{s3_key} (attempt {attempt + 1})")
                
                response = self.s3_client.get_object(Bucket=self.bucket_name, Key=s3_key)
                templates_data = json.loads(response['Body'].read().decode('utf-8'))
                
                logger.info(f"✅ Successfully downloaded templates: {len(templates_data)} templates")
                return templates_data
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchKey':
                    logger.error(f"❌ Templates file not found: s3://{self.bucket_name}/{s3_key}")
                    raise FileNotFoundError(f"Templates file not found: {s3_key}")
                elif attempt < max_retries - 1:
                    logger.warning(f"⚠️ S3 download failed (attempt {attempt + 1}): {e}. Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(f"❌ Failed to download templates after {max_retries} attempts: {e}")
                    raise
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"⚠️ Unexpected error downloading templates (attempt {attempt + 1}): {e}. Retrying...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    logger.error(f"❌ Failed to download templates after {max_retries} attempts: {e}")
                    raise
    
    def _ensure_domain_folders(self, domain: str) -> None:
        """
        Ensure domain folder structure exists in S3
        Creates: Organizations/{domain}/latest_findings/ and Organizations/{domain}/archive/
        
        Args:
            domain: Domain name (e.g., 'siemens.com')
        """
        folders_to_create = [
            f"Organizations/{domain}/latest_findings/",
            f"Organizations/{domain}/archive/"
        ]
        
        for folder_key in folders_to_create:
            try:
                # Create empty object to represent folder
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=folder_key,
                    Body=b'',
                    ContentType='application/x-directory'
                )
                logger.info(f"📁 Ensured folder exists: s3://{self.bucket_name}/{folder_key}")
            except ClientError as e:
                logger.error(f"❌ Failed to create folder {folder_key}: {e}")
                raise
    
    def _list_files_in_folder(self, folder_key: str) -> List[str]:
        """
        List all files in a specific S3 folder
        
        Args:
            folder_key: S3 folder key (e.g., 'Organizations/siemens.com/latest_findings/')
            
        Returns:
            List of file keys in the folder
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=folder_key,
                Delimiter='/'
            )
            
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    # Skip the folder marker itself
                    if not obj['Key'].endswith('/'):
                        files.append(obj['Key'])
            
            logger.info(f"📋 Found {len(files)} files in {folder_key}")
            return files
            
        except ClientError as e:
            logger.error(f"❌ Failed to list files in {folder_key}: {e}")
            raise
    
    def _move_files_to_archive(self, domain: str, files_to_move: List[str]) -> None:
        """
        Move files from latest_findings to archive folder
        
        Args:
            domain: Domain name
            files_to_move: List of file keys to move
        """
        if not files_to_move:
            logger.info("📂 No files to archive")
            return
        
        logger.info(f"📦 Moving {len(files_to_move)} files to archive...")
        
        for file_key in files_to_move:
            try:
                # Extract filename from the full key
                filename = file_key.split('/')[-1]
                archive_key = f"Organizations/{domain}/archive/{filename}"
                
                # Copy file to archive
                copy_source = {'Bucket': self.bucket_name, 'Key': file_key}
                self.s3_client.copy_object(
                    CopySource=copy_source,
                    Bucket=self.bucket_name,
                    Key=archive_key
                )
                
                # Delete original file
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=file_key)
                
                logger.info(f"📦 Moved {filename} to archive")
                
            except ClientError as e:
                logger.error(f"❌ Failed to move {file_key} to archive: {e}")
                raise
    
    def upload_attack_path_results(self, domain: str, organization_id: str, results_data: Dict[str, Any]) -> str:
        """
        Upload attack path results to S3 with proper archive management
        
        Args:
            domain: Domain name (e.g., 'siemens.com')
            organization_id: Organization ID
            results_data: Attack path results data to upload
            
        Returns:
            S3 key of the uploaded file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{organization_id}_scored_attack_paths_{timestamp}.json"
        
        try:
            # Step 1: Ensure domain folder structure exists
            logger.info(f"🏗️ Ensuring folder structure for domain: {domain}")
            self._ensure_domain_folders(domain)
            
            # Step 2: List existing files in latest_findings
            latest_findings_folder = f"Organizations/{domain}/latest_findings/"
            existing_files = self._list_files_in_folder(latest_findings_folder)
            
            # Step 3: Move existing files to archive
            if existing_files:
                logger.info(f"📦 Found {len(existing_files)} existing files, moving to archive...")
                self._move_files_to_archive(domain, existing_files)
            else:
                logger.info("📂 No existing files found in latest_findings")
            
            # Step 4: Upload new results to latest_findings
            latest_key = f"{latest_findings_folder}{filename}"
            
            # Add metadata to the results
            enhanced_results = {
                "metadata": {
                    "domain": domain,
                    "organization_id": organization_id,
                    "generated_timestamp": timestamp,
                    "generated_at": datetime.now().isoformat(),
                    "batch_execution": True
                },
                "results": results_data
            }
            
            # Upload with retry logic
            max_retries = 3
            retry_delay = 1
            
            for attempt in range(max_retries):
                try:
                    logger.info(f"📤 Uploading results to s3://{self.bucket_name}/{latest_key} (attempt {attempt + 1})")
                    
                    self.s3_client.put_object(
                        Bucket=self.bucket_name,
                        Key=latest_key,
                        Body=json.dumps(enhanced_results, indent=2).encode('utf-8'),
                        ContentType='application/json',
                        Metadata={
                            'domain': domain,
                            'organization_id': organization_id,
                            'generated_timestamp': timestamp
                        }
                    )
                    
                    logger.info(f"✅ Successfully uploaded results: s3://{self.bucket_name}/{latest_key}")
                    return latest_key
                    
                except ClientError as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"⚠️ Upload failed (attempt {attempt + 1}): {e}. Retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        retry_delay *= 2
                    else:
                        logger.error(f"❌ Failed to upload results after {max_retries} attempts: {e}")
                        raise
                        
        except Exception as e:
            logger.error(f"❌ Failed to upload attack path results: {e}")
            raise
    
    def verify_upload(self, s3_key: str) -> bool:
        """
        Verify that the uploaded file exists and is accessible
        
        Args:
            s3_key: S3 key to verify
            
        Returns:
            True if file exists and is accessible
        """
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            file_size = response.get('ContentLength', 0)
            logger.info(f"✅ Upload verified: {s3_key} ({file_size} bytes)")
            return True
        except ClientError as e:
            logger.error(f"❌ Upload verification failed for {s3_key}: {e}")
            return False
