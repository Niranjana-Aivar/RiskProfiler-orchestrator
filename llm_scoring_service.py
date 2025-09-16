import json
import logging
import asyncio
import random
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from models import (
    AttackPathInstance, LLMScoringInput, LLMScoringOutput, 
    ScoredAttackPath, StreamingPathUpdate
)
from config import settings

logger = logging.getLogger(__name__)


# ============================================================================
# PRODUCTION-GRADE BEDROCK THROTTLING AND RESILIENCE PATTERNS
# ============================================================================

class CircuitBreakerState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class ThrottlingMetrics:
    """Track throttling metrics for monitoring"""
    total_requests: int = 0
    throttled_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    circuit_breaker_trips: int = 0
    total_retry_time: float = 0.0
    max_retry_time: float = 0.0
    last_throttle_time: Optional[float] = None
    
    @property
    def throttle_rate(self) -> float:
        """Calculate current throttling rate"""
        return (self.throttled_requests / max(1, self.total_requests)) * 100
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        return (self.successful_requests / max(1, self.total_requests)) * 100


@dataclass 
class BedrockCircuitBreaker:
    """Circuit breaker pattern for Bedrock API resilience"""
    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: float = 60.0  # Seconds to wait before trying half-open
    success_threshold: int = 3  # Successes needed to close from half-open
    
    # State tracking
    state: CircuitBreakerState = field(default=CircuitBreakerState.CLOSED)
    failure_count: int = field(default=0)
    success_count: int = field(default=0)
    last_failure_time: Optional[float] = field(default=None)
    
    def can_execute(self) -> bool:
        """Check if request can be executed"""
        now = time.time()
        
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if now - (self.last_failure_time or 0) >= self.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                logger.info("Circuit breaker transitioning to HALF_OPEN")
                return True
            return False
        elif self.state == CircuitBreakerState.HALF_OPEN:
            return True
        
        return False
    
    def record_success(self):
        """Record successful request"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                logger.info("Circuit breaker CLOSED - service recovered")
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)  # Decay failures
    
    def record_failure(self):
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitBreakerState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                logger.warning(f"Circuit breaker OPEN after {self.failure_count} failures")
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker back to OPEN - recovery failed")


class ProductionBedrockThrottling:
    """Production-grade Bedrock throttling with all resilience patterns"""
    
    def __init__(self, 
                 max_retries: int = 8,
                 base_delay: float = 1.0,
                 max_delay: float = 120.0,
                 jitter_factor: float = 0.1,
                 concurrent_limit: int = 2,
                 adaptive_rate_limit: bool = True):
        
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_factor = jitter_factor
        self.concurrent_limit = concurrent_limit
        self.adaptive_rate_limit = adaptive_rate_limit
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(concurrent_limit)
        
        # Circuit breaker
        self.circuit_breaker = BedrockCircuitBreaker()
        
        # Metrics
        self.metrics = ThrottlingMetrics()
        
        # Adaptive rate limiting
        self.current_delay = 0.0
        self.last_success_time = time.time()
        
        # Dead letter queue for permanently failed requests
        self.dead_letter_queue: List[Dict[str, Any]] = []
    
    async def execute_with_resilience(self, 
                                    operation: Callable,
                                    *args,
                                    operation_id: str = "unknown",
                                    **kwargs) -> Any:
        """
        Execute operation with full production resilience patterns:
        - Circuit breaker
        - Exponential backoff with jitter  
        - Adaptive rate limiting
        - Comprehensive metrics
        - Dead letter queue
        """
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            self.metrics.circuit_breaker_trips += 1
            raise Exception(f"Circuit breaker OPEN - rejecting {operation_id}")
        
        # Concurrency limiting
        async with self.semaphore:
            return await self._execute_with_retries(operation, *args, operation_id=operation_id, **kwargs)
    
    async def _execute_with_retries(self, operation: Callable, *args, operation_id: str, **kwargs) -> Any:
        """Execute with exponential backoff and adaptive rate limiting"""
        
        self.metrics.total_requests += 1
        start_time = time.time()
        
        # Apply adaptive rate limiting
        if self.adaptive_rate_limit and self.current_delay > 0:
            await asyncio.sleep(self.current_delay)
        
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Execute the operation
                result = await operation(*args, **kwargs)
                
                # Record success
                self.metrics.successful_requests += 1
                self.circuit_breaker.record_success()
                self._adapt_rate_limit(success=True)
                
                return result
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                last_exception = e
                
                # Handle different error types
                if error_code == "ThrottlingException":
                    self.metrics.throttled_requests += 1
                    self.metrics.last_throttle_time = time.time()
                    
                    if attempt < self.max_retries:
                        delay = self._calculate_backoff_delay(attempt, is_throttling=True)
                        logger.warning(f"Bedrock throttling {operation_id} - attempt {attempt + 1}/{self.max_retries + 1}, waiting {delay:.2f}s")
                        await asyncio.sleep(delay)
                        continue
                    else:
                        logger.error(f"Max throttling retries exceeded for {operation_id}")
                        self._adapt_rate_limit(success=False, is_throttling=True)
                        
                elif error_code in ["ValidationException", "AccessDeniedException"]:
                    # Don't retry these - they're permanent failures
                    logger.error(f"Permanent error for {operation_id}: {error_code}")
                    break
                    
                elif error_code in ["InternalServerError", "ServiceUnavailableException"]:
                    # Retry these with backoff
                    if attempt < self.max_retries:
                        delay = self._calculate_backoff_delay(attempt, is_throttling=False)
                        logger.warning(f"Bedrock service error {operation_id} - attempt {attempt + 1}/{self.max_retries + 1}, waiting {delay:.2f}s")
                        await asyncio.sleep(delay)
                        continue
                    else:
                        logger.error(f"Max service error retries exceeded for {operation_id}")
                        
                else:
                    # Unknown error - don't retry
                    logger.error(f"Unknown Bedrock error for {operation_id}: {error_code}")
                    break
                    
            except Exception as e:
                # Non-Bedrock exceptions
                last_exception = e
                logger.error(f"Non-Bedrock error for {operation_id}: {e}")
                break
        
        # All retries failed
        self.metrics.failed_requests += 1
        self.circuit_breaker.record_failure()
        self._adapt_rate_limit(success=False)
        
        # Add to dead letter queue for analysis
        self.dead_letter_queue.append({
            "operation_id": operation_id,
            "timestamp": time.time(),
            "error": str(last_exception),
            "attempts": self.max_retries + 1
        })
        
        # Track retry time
        retry_time = time.time() - start_time
        self.metrics.total_retry_time += retry_time
        self.metrics.max_retry_time = max(self.metrics.max_retry_time, retry_time)
        
        raise last_exception
    
    def _calculate_backoff_delay(self, attempt: int, is_throttling: bool = False) -> float:
        """Calculate exponential backoff delay with jitter"""
        
        # More aggressive backoff for throttling
        base = self.base_delay * (3 if is_throttling else 2)
        
        # Exponential backoff: base * (2^attempt)
        delay = base * (2 ** attempt)
        
        # Cap at max delay
        delay = min(delay, self.max_delay)
        
        # Add jitter to avoid thundering herd
        jitter = delay * self.jitter_factor * random.random()
        delay += jitter
        
        return delay
    
    def _adapt_rate_limit(self, success: bool, is_throttling: bool = False):
        """Adaptive rate limiting based on success/failure patterns"""
        if not self.adaptive_rate_limit:
            return
            
        now = time.time()
        
        if success:
            # Gradually reduce delay on success
            self.current_delay *= 0.9
            self.current_delay = max(0, self.current_delay)
            self.last_success_time = now
        else:
            if is_throttling:
                # Increase delay more aggressively for throttling
                self.current_delay = min(self.max_delay, self.current_delay + 2.0)
            else:
                # Moderate increase for other failures
                self.current_delay = min(self.max_delay, self.current_delay + 0.5)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status for monitoring"""
        return {
            "circuit_breaker_state": self.circuit_breaker.state.value,
            "metrics": {
                "total_requests": self.metrics.total_requests,
                "success_rate": round(self.metrics.success_rate, 2),
                "throttle_rate": round(self.metrics.throttle_rate, 2),
                "circuit_breaker_trips": self.metrics.circuit_breaker_trips,
                "avg_retry_time": round(self.metrics.total_retry_time / max(1, self.metrics.failed_requests), 2),
                "max_retry_time": round(self.metrics.max_retry_time, 2)
            },
            "current_delay": round(self.current_delay, 2),
            "dead_letter_queue_size": len(self.dead_letter_queue),
            "last_throttle": self.metrics.last_throttle_time
        }
    
    def reset_circuit_breaker(self):
        """Manual circuit breaker reset for operations"""
        self.circuit_breaker.state = CircuitBreakerState.CLOSED
        self.circuit_breaker.failure_count = 0
        self.circuit_breaker.success_count = 0
        logger.info("Circuit breaker manually reset to CLOSED")
    
    def get_dead_letter_items(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent dead letter queue items for analysis"""
        return self.dead_letter_queue[-limit:] if self.dead_letter_queue else []


# Global production throttling instance
production_throttling = ProductionBedrockThrottling()


# ============================================================================
# LLM SCORING SERVICE WITH INTEGRATED THROTTLING
# ============================================================================


class LLMScoringService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.bedrock_client = None
        # Use the inference profile ARN as the primary model ID
        self.model_id = settings.LLM_INFERENCE_PROFILE_ARN
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS
        
        # Concurrency limiting is now handled by production_throttling
        
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
        """Call the LLM API via Bedrock with production-grade throttling"""
        return await production_throttling.execute_with_resilience(
            self._make_bedrock_request,
            prompt,
            operation_id=f"bedrock_llm_{hash(prompt[:100]) % 10000}"
        )
    
    async def _make_bedrock_request(self, prompt: str) -> str:
        """Make the actual Bedrock API request"""
        try:
            if not self.bedrock_client:
                await self.initialize()
            
            # Prepare the request payload for Claude-3.5 Sonnet
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
            
            # Make the API call using the configured model ID
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                body=request_body_json
            )
            
            # Parse the response
            response_body = json.loads(response['body'].read())
            
            # Claude-3.5 Sonnet response format
            if 'content' in response_body and isinstance(response_body['content'], list):
                for content_item in response_body['content']:
                    if content_item.get('text'):
                        return content_item['text']
            
            # Fallback response parsing
            return str(response_body)
                    
        except Exception as e:
            self.logger.error(f"Error calling Bedrock API with model {self.model_id}: {e}")
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

    async def score_attack_paths_from_json(
        self, 
        attack_paths_json: List[Dict[str, Any]], 
        chunk_size: int = 10,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Score a list of attack paths represented as JSON using the LLM.

        Args:
            attack_paths_json: List of AttackPathInstance-like dicts.
            chunk_size: Number of paths per LLM call.
            progress_callback: Optional callback(progress_chunk, total_chunks).

        Returns:
            List of successfully scored attack paths (with .scoring fields).
            Failed chunks are skipped, not replaced.
        """
        if not self.bedrock_client:
            await self.initialize()
            
        scored_templates = []
        
        for template in attack_paths_json:
            try:
                scored_template = await self._score_template(template, chunk_size, progress_callback)
                if scored_template:
                    scored_templates.append(scored_template)
            except Exception as e:
                logger.error(f"Failed to score template {template.get('path_id', 'unknown')}: {e}")
                continue
        
        return scored_templates

    async def _score_template(
        self, 
        template: Dict[str, Any], 
        chunk_size: int,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Score all possible paths in a single template"""
        possible_paths = template.get('possible_paths', [])
        if not possible_paths:
            logger.warning(f"Template {template.get('path_id')} has no possible paths")
            return template
        
        # Calculate total chunks for this template
        total_chunks = max(1, (len(possible_paths) + chunk_size - 1) // chunk_size)
        scored_paths = []
        
        logger.info(f"Scoring template {template.get('path_id')} with {len(possible_paths)} paths in {total_chunks} chunks")
        
        for idx in range(0, len(possible_paths), chunk_size):
            chunk = possible_paths[idx: idx + chunk_size]
            chunk_number = idx // chunk_size + 1
            
            try:
                # Create a mini-template for this chunk
                chunk_template = {
                    **template,
                    'possible_paths': chunk
                }
                
                scored_chunk_paths = await self._score_chunk_with_retry(chunk_template, max_retries=3)
                scored_paths.extend(scored_chunk_paths)
                
                logger.info(f"Successfully scored chunk {chunk_number}/{total_chunks} for template {template.get('path_id')}")
                
            except Exception as e:
                logger.error(f"Chunk {chunk_number}/{total_chunks} failed permanently for template {template.get('path_id')}: {e}")
                continue
            
            # Progress callback
            if progress_callback:
                progress_callback(chunk_number, total_chunks)
        
        # Create the final scored template
        scored_template = {
            **template,
            'possible_paths': scored_paths,
            'total_possible_paths': len(scored_paths)
        }
        
        # Sort paths by risk_score descending
        scored_template['possible_paths'] = sorted(
            scored_template['possible_paths'],
            key=lambda x: x.get("scoring", {}).get("risk_score", 0),
            reverse=True
        )
        
        return scored_template

    async def _score_chunk_with_retry(self, chunk_template: Dict[str, Any], max_retries: int = 3, base_delay: float = 1.0) -> List[Dict[str, Any]]:
        """
        Score a chunk using production-grade throttling (max_retries and base_delay are ignored - handled by production_throttling)
        """
        prompt = self._create_batch_prompt(chunk_template)
        response = await self._call_bedrock_api(prompt)
        results = self._parse_llm_batch_response(response, chunk_template)
        return results

    def _create_batch_prompt(self, template: Dict[str, Any]) -> str:
        """Create a batch prompt for scoring multiple paths in a template"""
        possible_paths = template.get('possible_paths', [])
        
        prompt = f"""You are a cybersecurity risk assessment expert working for a legitimate organization's defensive security team. Your role is to analyze potential attack paths to help the organization improve their security posture and defend against threats.

IMPORTANT DISCLAIMER: This analysis is for defensive cybersecurity purposes only - to help identify and mitigate vulnerabilities, not to enable attacks.

Please analyze the following attack path template and score each possible path for defensive risk assessment purposes.

**Attack Path Template:**
- ID: {template.get('path_id')}
- Name: {template.get('name')}
- Description: {template.get('description')}
- Goals: {', '.join(template.get('goals', []))}
- Outcomes: {', '.join(template.get('outcomes', []))}
- Nodes: {', '.join(template.get('nodes', []))}

**Possible Paths to Score:** {len(possible_paths)} paths

**Scoring Instructions:**
For each path, analyze the node data and provide differentiated scores based on specific details:

**SCORING DIFFERENTIATION FACTORS:**
- CVE severity levels and CVSS base scores
- Exploit availability and public exploit maturity
- CISA KEV status (higher priority)
- Attack vector complexity (NETWORK vs LOCAL vs ADJACENT)
- Authentication requirements (NONE > SINGLE > MULTIPLE)
- Asset exposure and internet accessibility
- Service versions and known vulnerabilities
- Asset activity patterns and last_seen timestamps
- Port exposure and service configurations from additional_info

1. **Likelihood Score (0.0-1.0):** How likely is this attack path to be exploited? Consider:
   - Vulnerability severity and exploit availability
   - CISA KEV status (prioritize paths with CISA KEV vulnerabilities)
   - Attack vector (NETWORK preferred over LOCAL)
   - Asset activity status and last_seen timestamps
   - Number and criticality of vulnerabilities
   - Service information from additional_info fields (ports, services, versions)
   - Asset exposure level (internet-facing assets have higher likelihood)

2. **Impact Score (0.0-1.0):** What would be the business impact if exploited? Consider:
   - Asset criticality and business function
   - Vulnerability severity (CRITICAL > HIGH > MEDIUM > LOW)
   - Number of vulnerabilities on the same asset
   - Asset role and importance in the infrastructure
   - Data sensitivity and business disruption potential
   - Service criticality from additional_info

3. **Risk Score:** Calculate as: (likelihood_score * 0.6 + impact_score * 0.4) * 100
   - **IMPORTANT**: Risk scores should be differentiated across paths to avoid ties
   - Use precise float values (e.g., 67.45, 82.31, 91.76) not rounded numbers
   - Range: 0.00 to 100.00 with 2 decimal places for clear ranking
   - Consider subtle differences in vulnerability criticality, exploit complexity, and asset exposure
   - Even similar paths should have slight score variations based on specific details

4. **Attack Steps:** Generate 3-5 defensive mitigation steps that security teams should prioritize to prevent this attack path:
   - Network monitoring and detection for reconnaissance activities
   - Asset hardening and vulnerability patching priorities  
   - Service configuration improvements and security controls
   - Access controls and authentication strengthening
   - Monitoring and alerting for suspicious activities

5. **Confidence Level:** High/Medium/Low based on:
   - Data quality and completeness
   - Specificity of vulnerability information
   - Asset information availability
   - Service and version details in additional_info

6. **Reasoning:** Explain your scoring with specific evidence references from:
   - Vulnerability details (CVE IDs, severity, exploit availability)
   - Asset information (IP, activity status, last_seen)
   - Service details from additional_info fields
   - CISA KEV status and public exploit availability

**Response Format (JSON Array):**
[
  {{
    "path_no": 1,
    "scoring": {{
      "likelihood_score": 0.8547,
      "impact_score": 0.7312,
      "risk_score": 80.37,
      "alpha": 0.6,
      "attack_steps": [
        "Step 1: Implement DNS monitoring to detect reconnaissance...",
        "Step 2: Deploy network segmentation and access controls...",
        "Step 3: Patch CVE vulnerabilities and harden services..."
      ],
      "confidence_level": "High",
      "reasoning": "Detailed explanation..."
    }}
  }},
  {{
    "path_no": 2,
    "scoring": {{
      "likelihood_score": 0.7821,
      "impact_score": 0.6943,
      "risk_score": 74.70,
      "alpha": 0.6,
      "attack_steps": [
        "Step 1: Different defensive monitoring approach...",
        "Step 2: Alternative security controls...",
        "Step 3: Specific mitigation for this path..."
      ],
      "confidence_level": "Medium",
      "reasoning": "Different reasoning for this path..."
    }}
  }}
]

**CRITICAL**: Ensure each path has a unique risk_score with 2 decimal places. No two paths should have identical scores.

**REMINDER**: This analysis is for defensive security purposes to help protect the organization from these attack paths.

**Paths Data:**
"""
        
        # Add each path's data - renumber sequentially for this chunk
        for i, path in enumerate(possible_paths, 1):
            prompt += f"\n**Path {i} (path_no: {i}):**\n"
            
            # Add node data for each path
            for node_name in template.get('nodes', []):
                if node_name in path:
                    node_data = path[node_name]
                    prompt += f"- {node_name}: {json.dumps(node_data, indent=2)}\n"
            
            prompt += "\n"
        
        prompt += "\nPlease provide your analysis in the exact JSON format above, with one scoring object per path."
        
        return prompt

    def _parse_llm_batch_response(self, response: str, template: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse the LLM batch response and merge with original path data"""
        try:
            # Extract JSON array from response
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end]
                parsed_scores = json.loads(json_str)
                
                # Merge scoring data with original paths
                possible_paths = template.get('possible_paths', [])
                scored_paths = []
                
                for i, path in enumerate(possible_paths):
                    scored_path = path.copy()
                    
                    # Match by sequential index (1, 2, 3...) since we renumbered in prompt
                    sequential_path_no = i + 1
                    matching_score = None
                    
                    for score in parsed_scores:
                        if score.get('path_no') == sequential_path_no:
                            matching_score = score.get('scoring', {})
                            break
                    
                    if matching_score:
                        scored_path['scoring'] = matching_score
                    else:
                        # Skip paths without LLM scores - no fallback
                        logger.error(f"No LLM score found for sequential path {sequential_path_no}, skipping path")
                        continue
                    
                    scored_paths.append(scored_path)
                
                return scored_paths
            else:
                # Fail if JSON extraction fails - no fallback
                raise ValueError("Could not extract JSON array from LLM response")
                
        except Exception as e:
            logger.error(f"Error parsing LLM batch response: {e}")
            raise
    
    def get_throttling_health_status(self) -> Dict[str, Any]:
        """Get comprehensive throttling and health metrics"""
        health_status = production_throttling.get_health_status()
        
        # Add LLM-specific context
        health_status['llm_model'] = self.model_id
        health_status['temperature'] = self.temperature
        health_status['max_tokens'] = self.max_tokens
        
        return health_status
    
    def reset_throttling_circuit_breaker(self):
        """Reset circuit breaker for manual intervention"""
        production_throttling.reset_circuit_breaker()
        logger.info("LLM throttling circuit breaker manually reset")
    
    def get_failed_requests_analysis(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent failed requests for debugging"""
        return production_throttling.get_dead_letter_items(limit)



# Global LLM scoring service instance
llm_scoring_service = LLMScoringService() 