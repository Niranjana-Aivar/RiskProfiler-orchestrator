import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import time

from models import (
    AttackPathInstance, ScoredAttackPath, 
    AttackPathResponse, StreamingPathUpdate
)
from database import db_manager
from attack_path_engine import attack_path_engine
from llm_scoring_service import llm_scoring_service
from cache_manager import build_org_data_cache, cache_manager
from config import settings

# Import Strands
from strands import Agent, tool

logger = logging.getLogger(__name__)


class AttackPathService:
    def __init__(self):
        self.db_manager = db_manager
        self.attack_path_engine = attack_path_engine
        self.llm_scoring_service = llm_scoring_service
        self.strands_agent = None
        
    async def initialize(self):
        """Initialize the service and load attack path templates"""
        try:
            # Initialize database connections
            await self.db_manager.initialize()
            
            # Initialize LLM scoring service
            await self.llm_scoring_service.initialize()
            
            # Load attack path templates
            await self.attack_path_engine.load_attack_path_templates()
            
            # Create Strands agent
            self.strands_agent = self._create_strands_agent()
            
            logger.info("Attack Path Service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Attack Path Service: {e}")
            raise
    
    def _create_strands_agent(self) -> Agent:
        """Create Strands agent with tools for attack path analysis"""
        system_prompt = """You are a cybersecurity expert specializing in attack path analysis and risk assessment.

Your role is to analyze attack paths for organizations and provide expert risk assessments.

When analyzing attack paths:
1. Consider the technical feasibility of exploitation
2. Assess the business impact if exploited
3. Evaluate the likelihood based on available evidence
4. Provide actionable remediation recommendations
5. Consider supporting and mitigating factors

Always provide structured, professional analysis with clear reasoning."""

        # Define tools for the Strands agent
        @tool
        def analyze_attack_path_risk(path_data: Dict[str, Any]) -> Dict[str, Any]:
            """Analyze the risk of an attack path based on available data"""
            try:
                # Extract key information
                path_name = path_data.get('path_name', 'Unknown')
                goals = path_data.get('goals', [])
                nodes_data = path_data.get('nodes_data', {})
                mitigating_evidence = path_data.get('mitigating_evidence', [])
                
                # Basic risk analysis
                risk_factors = []
                if mitigating_evidence:
                    risk_factors.append(f"Mitigating factors: {len(mitigating_evidence)} items")
                
                # Count assets by type
                asset_counts = {}
                for node_type, assets in nodes_data.items():
                    if isinstance(assets, list):
                        asset_counts[node_type] = len(assets)
                
                analysis = {
                    "path_name": path_name,
                    "goals": goals,
                    "risk_factors": risk_factors,
                    "asset_counts": asset_counts,
                    "analysis_timestamp": datetime.now().isoformat()
                }
                
                return analysis
                
            except Exception as e:
                logger.error(f"Error in attack path risk analysis: {e}")
                return {"error": str(e)}
        
        @tool
        def assess_asset_vulnerability(asset_type: str, asset_count: int, findings: List[Dict]) -> Dict[str, Any]:
            """Assess the vulnerability level of a specific asset type"""
            try:
                # Count findings by severity for this asset type
                severity_counts = {}
                for finding in findings:
                    if finding.get('asset_type') == asset_type:
                        severity = finding.get('severity', 'unknown')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Determine vulnerability level
                if severity_counts.get('critical', 0) > 0:
                    vulnerability_level = "critical"
                elif severity_counts.get('high', 0) > 0:
                    vulnerability_level = "high"
                elif severity_counts.get('medium', 0) > 0:
                    vulnerability_level = "medium"
                else:
                    vulnerability_level = "low"
                
                assessment = {
                    "asset_type": asset_type,
                    "asset_count": asset_count,
                    "vulnerability_level": vulnerability_level,
                    "severity_breakdown": severity_counts,
                    "recommendation": f"Focus on {vulnerability_level} severity findings for {asset_type}"
                }
                
                return assessment
                
            except Exception as e:
                logger.error(f"Error in asset vulnerability assessment: {e}")
                return {"error": str(e)}
        
        @tool
        def generate_remediation_plan(path_data: Dict[str, Any], risk_score: float) -> Dict[str, Any]:
            """Generate a remediation plan for an attack path"""
            try:
                path_name = path_data.get('path_name', 'Unknown')
                goals = path_data.get('goals', [])
                
                # Generate remediation steps based on risk score
                if risk_score >= 0.8:
                    priority = "Immediate"
                    timeline = "24-48 hours"
                elif risk_score >= 0.6:
                    priority = "High"
                    timeline = "1 week"
                elif risk_score >= 0.4:
                    priority = "Medium"
                    timeline = "2 weeks"
                else:
                    priority = "Low"
                    timeline = "1 month"
                
                remediation_plan = {
                    "path_name": path_name,
                    "risk_score": risk_score,
                    "priority": priority,
                    "timeline": timeline,
                    "goals_impacted": goals,
                    "remediation_steps": [
                        "Assess current security controls",
                        "Implement missing security measures",
                        "Monitor for exploitation attempts",
                        "Conduct security testing"
                    ]
                }
                
                return remediation_plan
                
            except Exception as e:
                logger.error(f"Error generating remediation plan: {e}")
                return {"error": str(e)}
        
        # Create agent with tools
        agent = Agent(
            system_prompt=system_prompt,
            tools=[analyze_attack_path_risk, assess_asset_vulnerability, generate_remediation_plan]
        )
        
        logger.info("Strands agent created with attack path analysis tools")
        return agent
    
    async def close(self):
        """Close the service and database connections"""
        await self.db_manager.close()
        logger.info("Attack Path Service closed")
    
    async def generate_attack_paths(self, domain: str, top_n: int = 10, 
                                   progress_callback: Optional[Callable] = None) -> AttackPathResponse:
        """Generate attack paths for a given domain"""
        start_time = time.time()
        
        try:
            # Step 1: Resolve organization and scan
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="init",
                    path_name="Initialization",
                    status="started",
                    progress=0.0,
                    message=f"Resolving organization for domain: {domain}"
                ))
            
            organization = await self._resolve_organization(domain)
            if not organization:
                raise ValueError(f"Organization not found for domain: {domain}")
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="init",
                    path_name="Initialization",
                    status="completed",
                    progress=0.1,
                    message=f"Found organization: {organization['id']} (scan: {organization['latest_scan_id']})"
                ))
            
            # Step 2: Gather organization context and asset summary
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="context",
                    path_name="Context Gathering",
                    status="started",
                    progress=0.1,
                    message="Gathering organization context and asset summary..."
                ))
            
            organization_context = await self._gather_organization_context(organization['id'])
            asset_summary = await self._create_asset_summary(organization['id'])
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="context",
                    path_name="Context Gathering",
                    status="completed",
                    progress=0.2,
                    message=f"Gathered context: {len(organization_context)} data points"
                ))
            
            # Step 3: Build data cache
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="cache",
                    path_name="Data Cache",
                    status="started",
                    progress=0.2,
                    message="Building organization data cache..."
                ))
            
            cache = await build_org_data_cache(
                self.db_manager, 
                organization['id'], 
                organization['latest_scan_id']
            )
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="cache",
                    path_name="Data Cache",
                    status="completed",
                    progress=0.25,
                    message=f"Built cache with {len(cache)} tables"
                ))
            
            # Step 4: Instantiate attack paths
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="instantiation",
                    path_name="Path Instantiation",
                    status="started",
                    progress=0.25,
                    message="Instantiating attack paths from templates..."
                ))
            
            path_instances = await self.attack_path_engine.instantiate_attack_paths(
                organization['id'], organization['latest_scan_id'], cache
            )
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="instantiation",
                    path_name="Path Instantiation",
                    status="completed",
                    progress=0.45,
                    message=f"Generated {len(path_instances)} attack path instances"
                ))
            
            if not path_instances:
                logger.warning(f"No attack paths found for organization {organization['id']}")
                return self._create_empty_response(organization, domain, start_time)
            
            # Step 4: Use Strands agent for enhanced analysis
            # if progress_callback:
            #     await progress_callback(StreamingPathUpdate(
            #         path_id="strands_analysis",
            #         path_name="Strands Analysis",
            #         status="started",
            #         progress=0.4,
            #         message="Using Strands agent for enhanced attack path analysis..."
            #     ))
            #
            # # Analyze each path with Strands agent
            # enhanced_paths = []
            # for i, path_instance in enumerate(path_instances):
            #     try:
            #         # Use Strands agent to analyze the path
            #         analysis_result = await self._analyze_with_strands(path_instance)
            #         
            #         # Merge analysis results
            #         enhanced_path = path_instance.model_copy(update=analysis_result)
            #         enhanced_paths.append(enhanced_path)
            #         
            #         if progress_callback:
            #             progress = 0.4 + (0.2 * (i + 1) / len(path_instances))
            #             await progress_callback(StreamingPathUpdate(
            #                 path_id=path_instance.path_id,
            #                 path_name=path_instance.path_name,
            #                 status="analyzed",
            #                 progress=progress,
            #                 message=f"Enhanced analysis completed for {path_instance.path_name}"
            #             ))
            #             
            #     except Exception as e:
            #         logger.warning(f"Error in Strands analysis for {path_instance.path_id}: {e}")
            #         enhanced_paths.append(path_instance)
            #
            # if progress_callback:
            #     await progress_callback(StreamingPathUpdate(
            #         path_id="strands_analysis",
            #         path_name="Strands Analysis",
            #         status="completed",
            #         progress=0.6,
            #         message=f"Enhanced {len(enhanced_paths)} attack paths with Strands analysis"
            #     ))

            # Instead, use path_instances directly for scoring below
            enhanced_paths = path_instances
            
            # Step 5: Score attack paths using LLM
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="scoring",
                    path_name="LLM Scoring",
                    status="started",
                    progress=0.6,
                    message="Scoring attack paths using AI analysis..."
                ))
            
            scored_paths = await self.llm_scoring_service.score_multiple_paths(
                enhanced_paths, organization_context, asset_summary, progress_callback
            )
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="scoring",
                    path_name="LLM Scoring",
                    status="completed",
                    progress=0.9,
                    message=f"Scored {len(scored_paths)} attack paths"
                ))
            
            # Step 6: Select top N paths
            top_paths = scored_paths[:top_n]
            
            if progress_callback:
                await progress_callback(StreamingPathUpdate(
                    path_id="finalization",
                    path_name="Finalization",
                    status="completed",
                    progress=1.0,
                    message=f"Generated top {len(top_paths)} attack paths"
                ))
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Create response
            response = AttackPathResponse(
                organization_id=organization['id'],
                domain=domain,
                scan_id=organization['latest_scan_id'],
                total_paths_found=len(path_instances),
                top_paths=top_paths,
                processing_time_seconds=processing_time,
                generated_at=datetime.now()
            )
            
            logger.info(f"Generated {len(top_paths)} attack paths for {domain} in {processing_time:.2f}s")
            
            # Clean up cache for this request
            cache_manager.clear_cache(organization['id'], organization['latest_scan_id'])
            cache_manager.log_cache_stats()
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating attack paths for {domain}: {e}")
            raise
    
    async def _analyze_with_strands(self, path_instance: AttackPathInstance) -> Dict[str, Any]:
        """Use Strands agent to analyze an attack path"""
        try:
            if not self.strands_agent:
                logger.warning("Strands agent not available, skipping enhanced analysis")
                return {}
            
            # Prepare data for Strands analysis
            path_data = {
                "path_name": path_instance.path_name,
                "goals": path_instance.goals,
                "nodes_data": path_instance.nodes_data,
                "mitigating_evidence": path_instance.mitigating_evidence
            }
            
            # Use Strands agent to analyze the path
            analysis_prompt = f"""Analyze the following attack path and provide risk assessment:

Path: {path_instance.path_name}
Goals: {', '.join(path_instance.goals)}
Nodes: {len(path_instance.nodes_data)} data nodes
Mitigating Evidence: {len(path_instance.mitigating_evidence)} items

Please use the available tools to:
1. Analyze the attack path risk
2. Assess asset vulnerabilities
3. Generate remediation recommendations

Provide a comprehensive analysis."""

            # Invoke Strands agent
            result = self.strands_agent(analysis_prompt)
            
            # Extract analysis results
            analysis_result = {}
            if result and hasattr(result, 'message'):
                analysis_result['strands_analysis'] = str(result.message)
            else:
                analysis_result['strands_analysis'] = str(result)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in Strands analysis: {e}")
            return {"strands_analysis": "Analysis failed due to error"}
    
    async def _resolve_organization(self, domain: str) -> Optional[Dict[str, Any]]:
        """Resolve organization by domain"""
        try:
            organization = await self.db_manager.get_organization_by_domain(domain)
            if not organization:
                logger.warning(f"Organization not found for domain: {domain}")
                return None
            
            logger.info(f"Resolved organization {organization['id']} for domain {domain}")
            return organization
            
        except Exception as e:
            logger.error(f"Error resolving organization for domain {domain}: {e}")
            raise
    
    async def _gather_organization_context(self, organization_id: str) -> Dict[str, Any]:
        """Gather comprehensive organization context"""
        try:
            context = {}
            
            # Gather various data sources
            context['total_findings'] = await self._count_findings(organization_id)
            context['total_cves'] = await self._count_cves(organization_id)
            context['total_dns_records'] = await self._count_dns_records(organization_id)
            context['total_ip_ranges'] = await self._count_ip_ranges(organization_id)
            context['total_login_urls'] = await self._count_login_urls(organization_id)
            context['total_email_addresses'] = await self._count_email_addresses(organization_id)
            context['total_email_breaches'] = await self._count_email_breaches(organization_id)
            context['total_apis'] = await self._count_apis(organization_id)
            context['total_object_storages'] = await self._count_object_storages(organization_id)
            context['total_cdns'] = await self._count_cdns(organization_id)
            context['total_domain_names'] = await self._count_domain_names(organization_id)
            context['total_phishing_results'] = await self._count_phishing_results(organization_id)
            context['total_typosquatting_domains'] = await self._count_typosquatting_domains(organization_id)
            
            # Add severity breakdowns
            context['severity_breakdown'] = await self._get_severity_breakdown(organization_id)
            
            logger.info(f"Gathered context for organization {organization_id}: {len(context)} data points")
            return context
            
        except Exception as e:
            logger.error(f"Error gathering organization context for {organization_id}: {e}")
            return {}
    
    async def _create_asset_summary(self, organization_id: str) -> Dict[str, Any]:
        """Create a summary of assets for the organization"""
        try:
            summary = {}
            
            # Get sample assets from each category
            summary['dns_records'] = await self._get_sample_dns_records(organization_id)
            summary['ip_ranges'] = await self._get_sample_ip_ranges(organization_id)
            summary['login_urls'] = await self._get_sample_login_urls(organization_id)
            summary['email_addresses'] = await self._get_sample_email_addresses(organization_id)
            summary['apis'] = await self._get_sample_apis(organization_id)
            summary['object_storages'] = await self._get_sample_object_storages(organization_id)
            summary['cdns'] = await self._get_sample_cdns(organization_id)
            summary['domain_names'] = await self._get_sample_domain_names(organization_id)
            
            logger.info(f"Created asset summary for organization {organization_id}")
            return summary
            
        except Exception as e:
            logger.error(f"Error creating asset summary for {organization_id}: {e}")
            return {}
    
    async def _count_findings(self, organization_id: str) -> int:
        """Count total findings for organization"""
        try:
            # This would need to be implemented based on your data model
            # For now, return a placeholder
            return 0
        except Exception:
            return 0
    
    async def _count_cves(self, organization_id: str) -> int:
        """Count total CVEs for organization"""
        try:
            cves = await self.db_manager.get_organization_cves(organization_id)
            return len(cves)
        except Exception:
            return 0
    
    async def _count_dns_records(self, organization_id: str) -> int:
        """Count total DNS records for organization"""
        try:
            dns_records = await self.db_manager.get_organization_dns(organization_id)
            return len(dns_records)
        except Exception:
            return 0
    
    async def _count_ip_ranges(self, organization_id: str) -> int:
        """Count total IP ranges for organization"""
        try:
            ip_ranges = await self.db_manager.get_organization_ip_ranges(organization_id)
            return len(ip_ranges)
        except Exception:
            return 0
    
    async def _count_login_urls(self, organization_id: str) -> int:
        """Count total login URLs for organization"""
        try:
            login_urls = await self.db_manager.get_organization_login_urls(organization_id)
            return len(login_urls)
        except Exception:
            return 0
    
    async def _count_email_addresses(self, organization_id: str) -> int:
        """Count total email addresses for organization"""
        try:
            email_addresses = await self.db_manager.get_organization_email_addresses(organization_id)
            return len(email_addresses)
        except Exception:
            return 0
    
    async def _count_email_breaches(self, organization_id: str) -> int:
        """Count total email breaches for organization"""
        try:
            email_breaches = await self.db_manager.get_organization_email_breaches(organization_id)
            return len(email_breaches)
        except Exception:
            return 0
    
    async def _count_apis(self, organization_id: str) -> int:
        """Count total APIs for organization"""
        try:
            apis = await self.db_manager.get_organization_apis(organization_id)
            return len(apis)
        except Exception:
            return 0
    
    async def _count_object_storages(self, organization_id: str) -> int:
        """Count total object storages for organization"""
        try:
            object_storages = await self.db_manager.get_organization_object_storages(organization_id)
            return len(object_storages)
        except Exception:
            return 0
    
    async def _count_cdns(self, organization_id: str) -> int:
        """Count total CDNs for organization"""
        try:
            cdns = await self.db_manager.get_organization_cdns(organization_id)
            return len(cdns)
        except Exception:
            return 0
    
    async def _count_domain_names(self, organization_id: str) -> int:
        """Count total domain names for organization"""
        try:
            domain_names = await self.db_manager.get_organization_domain_names(organization_id)
            return len(domain_names)
        except Exception:
            return 0
    
    async def _count_phishing_results(self, organization_id: str) -> int:
        """Count total phishing results for organization"""
        try:
            phishing_results = await self.db_manager.get_phishing_results(organization_id)
            return len(phishing_results)
        except Exception:
            return 0
    
    async def _count_typosquatting_domains(self, organization_id: str) -> int:
        """Count total typosquatting domains for organization"""
        try:
            typosquatting_domains = await self.db_manager.get_typosquatting_domains(organization_id)
            return len(typosquatting_domains)
        except Exception:
            return 0
    
    async def _get_severity_breakdown(self, organization_id: str) -> Dict[str, int]:
        """Get severity breakdown for organization"""
        try:
            # This would need to be implemented based on your data model
            # For now, return a placeholder
            return {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        except Exception:
            return {}
    
    async def _get_sample_dns_records(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample DNS records for organization"""
        try:
            dns_records = await self.db_manager.get_organization_dns(organization_id)
            return [record['name'] for record in dns_records[:limit]]
        except Exception:
            return []
    
    async def _get_sample_ip_ranges(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample IP ranges for organization"""
        try:
            ip_ranges = await self.db_manager.get_organization_ip_ranges(organization_id)
            return [ip_range['ip_range'] for ip_range in ip_ranges[:limit]]
        except Exception:
            return []
    
    async def _get_sample_login_urls(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample login URLs for organization"""
        try:
            login_urls = await self.db_manager.get_organization_login_urls(organization_id)
            return [url['url'] for url in login_urls[:limit]]
        except Exception:
            return []
    
    async def _get_sample_email_addresses(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample email addresses for organization"""
        try:
            email_addresses = await self.db_manager.get_organization_email_addresses(organization_id)
            return [email['email'] for email in email_addresses[:limit]]
        except Exception:
            return []
    
    async def _get_sample_apis(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample APIs for organization"""
        try:
            apis = await self.db_manager.get_organization_apis(organization_id)
            return [api['root_endpoint'] for api in apis[:limit]]
        except Exception:
            return []
    
    async def _get_sample_object_storages(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample object storages for organization"""
        try:
            object_storages = await self.db_manager.get_organization_object_storages(organization_id)
            return [storage['endpoint'] for storage in object_storages[:limit]]
        except Exception:
            return []
    
    async def _get_sample_cdns(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample CDNs for organization"""
        try:
            cdns = await self.db_manager.get_organization_cdns(organization_id)
            return [cdn['endpoint'] for cdn in cdns[:limit]]
        except Exception:
            return []
    
    async def _get_sample_domain_names(self, organization_id: str, limit: int = 5) -> List[str]:
        """Get sample domain names for organization"""
        try:
            domain_names = await self.db_manager.get_organization_domain_names(organization_id)
            return [domain['domain'] for domain in domain_names[:limit]]
        except Exception:
            return []
    
    def _create_empty_response(self, organization: Dict[str, Any], domain: str, start_time: float) -> AttackPathResponse:
        """Create an empty response when no attack paths are found"""
        processing_time = time.time() - start_time
        
        return AttackPathResponse(
            organization_id=organization['id'],
            domain=domain,
            scan_id=organization['latest_scan_id'],
            total_paths_found=0,
            top_paths=[],
            processing_time_seconds=processing_time,
            generated_at=datetime.now()
        )


# Global attack path service instance
attack_path_service = AttackPathService() 