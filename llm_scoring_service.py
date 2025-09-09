import json
import logging
import asyncio
import random
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional
from datetime import datetime

from models import (
    AttackPathInstance, LLMScoringInput, LLMScoringOutput, 
    ScoredAttackPath, StreamingPathUpdate
)
from config import settings

logger = logging.getLogger(__name__)


async def call_bedrock_with_retries(call_fn, *args, max_attempts=5, base_delay=1.0, max_delay=30.0, **kwargs):
    """Exponential backoff with jitter for Bedrock API calls"""
    for attempt in range(max_attempts):
        try:
            return await call_fn(*args, **kwargs)
        except ClientError as e:
            # Check for ThrottlingException
            if e.response.get("Error", {}).get("Code") == "ThrottlingException":
                if attempt < max_attempts - 1:  # Don't sleep on the last attempt
                    # Exponential backoff with jitter
                    sleep = min(max_delay, base_delay * (2 ** attempt) + random.uniform(0, 1))
                    logger.warning(f"Bedrock throttled, retrying in {sleep:.1f}s (attempt {attempt + 1}/{max_attempts})")
                    await asyncio.sleep(sleep)
                else:
                    logger.error(f"Bedrock throttling retries exhausted after {max_attempts} attempts")
                    raise
            else:
                # Other ClientError types: re-raise immediately
                raise
        except Exception as e:
            # Non-ClientError exceptions: re-raise immediately
            raise
    raise Exception("Too many requests to Bedrock. Retries exhausted.")


class LLMScoringService:
    def __init__(self):
        self.bedrock_client = None
        self.inference_profile_arn = settings.LLM_INFERENCE_PROFILE_ARN
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS
        
        # Concurrency limiting - configurable concurrent Bedrock calls
        self.bedrock_semaphore = asyncio.Semaphore(settings.LLM_CONCURRENT_CALLS)
        
        # Boto3 configuration with increased timeouts
        self.boto3_config = Config(
            read_timeout=300,  # 5 minutes
            connect_timeout=60,  # 1 minute
            retries={'max_attempts': 1}  # Reduced since we handle retries ourselves
        )
        
    async def initialize(self):
        """Initialize the Bedrock client"""
        try:
            self.bedrock_client = boto3.client(
                'bedrock-runtime',
                region_name=settings.AWS_REGION,
                config=self.boto3_config
            )
            logger.info("Bedrock client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            raise
    
    async def score_attack_path(self, path_instance: AttackPathInstance, 
                               organization_context: Dict[str, Any],
                               asset_summary: Dict[str, Any]) -> LLMScoringOutput:
        """Score an attack path using the LLM via Bedrock"""
        try:
            # Prepare the input for LLM
            llm_input = LLMScoringInput(
                path_instance=path_instance,
                organization_context=organization_context,
                asset_summary=asset_summary
            )
            
            # Create the prompt
            prompt = self._create_scoring_prompt(llm_input)
            
            # Call the LLM API via Bedrock
            response = await self._call_bedrock_api(prompt)
            
            # Parse the response
            scoring_output = self._parse_llm_response(response, path_instance)
            
            return scoring_output
            
        except Exception as e:
            logger.error(f"Error scoring attack path {path_instance.path_id}: {e}")
            # Return default scoring on error
            return self._create_default_scoring(path_instance)
    
    def _create_scoring_prompt(self, llm_input: LLMScoringInput) -> str:
        """Create the prompt for LLM scoring"""
        path = llm_input.path_instance
        
        prompt = f"""You are a cybersecurity expert analyzing attack paths for an organization. 

Please analyze the following attack path and provide a comprehensive risk assessment.

**Attack Path Details:**
- ID: {path.path_id}
- Name: {path.path_name}
- Description: {path.path_description}
- Goals: {', '.join(path.goals)}
- Outcomes: {', '.join(path.outcomes)}

**Required Nodes Present:** {path.required_nodes_present}
**Optional Nodes Present:** {', '.join(path.optional_nodes_present) if path.optional_nodes_present else 'None'}

**Mitigating Evidence:** {', '.join(path.mitigating_evidence) if path.mitigating_evidence else 'None'}

**Asset Summary:**
{self._format_asset_summary(llm_input.asset_summary)}

**Organization Context:**
{self._format_organization_context(llm_input.organization_context)}

**Scoring Instructions:**
1. **Likelihood Score (0.0-1.0):** How likely is this attack path to be exploited? Consider:
   - Ease of exploitation
   - Availability of exploits
   - Required privileges
   - Attack complexity
   - Public exploit availability
   - CISA KEV status

2. **Impact Score (0.0-1.0):** What would be the business impact if exploited? Consider:
   - Asset criticality
   - Data sensitivity
   - Business function disruption
   - Regulatory implications
   - Reputation damage

3. **Risk Score:** Calculate as: Risk = 0.6 × Likelihood + 0.4 × Impact

4. **Confidence Level:** High/Medium/Low based on evidence quality

5. **Attack Steps:** Provide 3-5 specific steps an attacker would take

6. **Rationale:** Explain your scoring with specific evidence references

**Response Format (JSON):**
{{
    "risk_score": 0.85,
    "likelihood_score": 0.9,
    "impact_score": 0.75,
    "rationale": "Detailed explanation of scoring...",
    "attack_steps": [
        "Step 1: Reconnaissance...",
        "Step 2: Initial access...",
        "Step 3: Exploitation..."
    ],
    "confidence_level": "High"
}}

Please provide your analysis in the exact JSON format above."""

        return prompt
    
    def _format_asset_summary(self, asset_summary: Dict[str, Any]) -> str:
        """Format asset summary for the prompt"""
        if not asset_summary:
            return "No asset summary available"
        
        formatted = []
        for asset_type, assets in asset_summary.items():
            if isinstance(assets, list) and assets:
                count = len(assets)
                sample = assets[0] if assets else None
                if sample:
                    formatted.append(f"- {asset_type}: {count} assets (e.g., {sample})")
                else:
                    formatted.append(f"- {asset_type}: {count} assets")
            else:
                formatted.append(f"- {asset_type}: {assets}")
        
        return "\n".join(formatted)
    
    def _format_organization_context(self, org_context: Dict[str, Any]) -> str:
        """Format organization context for the prompt"""
        if not org_context:
            return "No organization context available"
        
        formatted = []
        for key, value in org_context.items():
            if isinstance(value, list):
                formatted.append(f"- {key}: {len(value)} items")
            else:
                formatted.append(f"- {key}: {value}")
        
        return "\n".join(formatted)
    
    async def _call_bedrock_api(self, prompt: str) -> str:
        """Call the LLM API via Bedrock with concurrency limiting"""
        async with self.bedrock_semaphore:
            return await call_bedrock_with_retries(
                self._make_bedrock_request, 
                prompt,
                max_attempts=settings.LLM_MAX_RETRY_ATTEMPTS,
                base_delay=settings.LLM_BASE_RETRY_DELAY,
                max_delay=settings.LLM_MAX_RETRY_DELAY
            )
    
    async def _make_bedrock_request(self, prompt: str) -> str:
        """Make the actual Bedrock API request"""
        try:
            if not self.bedrock_client:
                await self.initialize()
            
            # Prepare the request payload for Claude
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            # Convert to JSON string
            request_body_json = json.dumps(request_body)
            
            # Make the API call using inference profile ARN
            response = self.bedrock_client.invoke_model(
                modelId=self.inference_profile_arn,
                body=request_body_json
            )
            
            # Parse the response
            response_body = json.loads(response['body'].read())
            
            if 'content' in response_body:
                # Extract the text content from Claude's response
                content = response_body['content']
                if isinstance(content, list) and len(content) > 0:
                    return content[0].get('text', '')
                elif isinstance(content, dict):
                    return content.get('text', '')
            
            # Fallback response parsing
            return str(response_body)
                    
        except Exception as e:
            logger.error(f"Error calling Bedrock API: {e}")
            raise
    
    def _parse_llm_response(self, response: str, path_instance: AttackPathInstance) -> LLMScoringOutput:
        """Parse the LLM response into structured output"""
        try:
            # Try to extract JSON from the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                
                return LLMScoringOutput(
                    risk_score=float(parsed.get('risk_score', 0.5)),
                    likelihood_score=float(parsed.get('likelihood_score', 0.5)),
                    impact_score=float(parsed.get('impact_score', 0.5)),
                    rationale=parsed.get('rationale', 'No rationale provided'),
                    attack_steps=parsed.get('attack_steps', ['No attack steps provided']),
                    confidence_level=parsed.get('confidence_level', 'Medium')
                )
            else:
                # Fallback parsing if JSON extraction fails
                return self._fallback_parsing(response, path_instance)
                
        except Exception as e:
            logger.warning(f"Error parsing LLM response: {e}")
            return self._create_default_scoring(path_instance)
    
    def _fallback_parsing(self, response: str, path_instance: AttackPathInstance) -> LLMScoringOutput:
        """Fallback parsing for LLM response"""
        # Try to extract scores using regex or simple text parsing
        risk_score = 0.5
        likelihood_score = 0.5
        impact_score = 0.5
        
        # Simple heuristic scoring based on path characteristics
        if 'critical' in path_instance.path_name.lower() or 'critical' in str(path_instance.nodes_data).lower():
            risk_score = 0.8
            likelihood_score = 0.7
            impact_score = 0.9
        elif 'high' in path_instance.path_name.lower() or 'high' in str(path_instance.nodes_data).lower():
            risk_score = 0.7
            likelihood_score = 0.6
            impact_score = 0.8
        elif 'medium' in path_instance.path_name.lower() or 'medium' in str(path_instance.nodes_data).lower():
            risk_score = 0.5
            likelihood_score = 0.5
            impact_score = 0.5
        else:
            risk_score = 0.3
            likelihood_score = 0.3
            impact_score = 0.3
        
        return LLMScoringOutput(
            risk_score=risk_score,
            likelihood_score=likelihood_score,
            impact_score=impact_score,
            rationale=f"Fallback scoring based on path characteristics. Original response: {response[:200]}...",
            attack_steps=["Attack steps could not be parsed from LLM response"],
            confidence_level="Low"
        )
    
    def _create_default_scoring(self, path_instance: AttackPathInstance) -> LLMScoringOutput:
        """Create default scoring when LLM fails"""
        return LLMScoringOutput(
            risk_score=0.5,
            likelihood_score=0.5,
            impact_score=0.5,
            rationale="Default scoring due to LLM processing error",
            attack_steps=["Attack steps could not be determined"],
            confidence_level="Low"
        )
    
    async def score_multiple_paths(self, path_instances: List[AttackPathInstance],
                                  organization_context: Dict[str, Any],
                                  asset_summary: Dict[str, Any],
                                  progress_callback=None) -> List[ScoredAttackPath]:
        """Score multiple attack paths with progress tracking"""
        scored_paths = []
        
        for i, path_instance in enumerate(path_instances):
            try:
                # Score the path
                scoring_output = await self.score_attack_path(
                    path_instance, organization_context, asset_summary
                )
                
                # Create scored attack path
                scored_path = ScoredAttackPath(
                    path_id=path_instance.path_id,
                    path_name=path_instance.path_name,
                    path_description=path_instance.path_description,
                    goals=path_instance.goals,
                    risk_score=scoring_output.risk_score,
                    likelihood_score=scoring_output.likelihood_score,
                    impact_score=scoring_output.impact_score,
                    rationale=scoring_output.rationale,
                    attack_steps=scoring_output.attack_steps,
                    confidence_level=scoring_output.confidence_level,
                    nodes_data=path_instance.nodes_data,
                    mitigating_evidence=path_instance.mitigating_evidence,
                    outcomes=path_instance.outcomes
                )
                
                scored_paths.append(scored_path)
                
                # Report progress
                if progress_callback:
                    progress = (i + 1) / len(path_instances)
                    update = StreamingPathUpdate(
                        path_id=path_instance.path_id,
                        path_name=path_instance.path_name,
                        status="scored",
                        progress=progress,
                        message=f"Scored {path_instance.path_name} (Risk: {scoring_output.risk_score:.2f})"
                    )
                    await progress_callback(update)
                
                # Configurable delay to avoid overwhelming the API
                await asyncio.sleep(settings.LLM_CALL_DELAY)
                
            except Exception as e:
                # Enhanced error logging with throttling detection
                if isinstance(e, ClientError) and e.response.get("Error", {}).get("Code") == "ThrottlingException":
                    logger.warning(f"ThrottlingException for path {path_instance.path_id}: {e}")
                else:
                    logger.error(f"Error scoring path {path_instance.path_id}: {e}")
                continue
        
        # Sort by risk score (descending)
        scored_paths.sort(key=lambda x: x.risk_score, reverse=True)
        
        return scored_paths
    
    def calculate_final_risk_score(self, likelihood_score: float, impact_score: float) -> float:
        """Calculate final risk score using configured weights"""
        risk_score = (settings.LIKELIHOOD_WEIGHT * likelihood_score + 
                     settings.IMPACT_WEIGHT * impact_score)
        return min(max(risk_score, 0.0), 1.0)  # Clamp to [0, 1]


# Global LLM scoring service instance
llm_scoring_service = LLMScoringService() 