from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime


class AttackPathNode(BaseModel):
    order: int
    node_type: str
    table: str
    columns: List[str]
    selector: Dict[str, Any]
    join: List[Dict[str, str]]
    optional: bool

# class AttackPathTemplate(BaseModel):
#     version: str
#     source_rules_file: str
#     table_columns_canonical: Dict[str, List[str]]
#     paths: List[AttackPath]

class AttackPath(BaseModel):
    id: str
    name: str
    goals: List[str]
    description: str
    nodes: List[AttackPathNode]
    trigger_rules: List[str]
    supporting_rules: List[str]
    mitigation_rules: List[str]
    outcomes: List[str]


class AttackPathInstance(BaseModel):
    path_id: str
    path_name: str
    path_description: str
    goals: List[str]
    nodes_data: Dict[str, Any]
    required_nodes_present: bool
    optional_nodes_present: List[str]
    mitigating_evidence: List[str]
    outcomes: List[str]


class LLMScoringInput(BaseModel):
    path_instance: AttackPathInstance
    organization_context: Dict[str, Any]
    asset_summary: Dict[str, Any]


class LLMScoringOutput(BaseModel):
    risk_score: float  # 0.0 - 1.0
    likelihood_score: float  # 0.0 - 1.0
    impact_score: float  # 0.0 - 1.0
    rationale: str
    attack_steps: List[str]
    confidence_level: str


class ScoredAttackPath(BaseModel):
    path_id: str
    path_name: str
    path_description: str
    goals: List[str]
    risk_score: float
    likelihood_score: float
    impact_score: float
    rationale: str
    attack_steps: List[str]
    confidence_level: str
    nodes_data: Dict[str, Any]
    mitigating_evidence: List[str]
    outcomes: List[str]


class AttackPathRequest(BaseModel):
    domain: str
    top_n: Optional[int] = 10
    include_streaming: bool = True


class AttackPathResponse(BaseModel):
    organization_id: str
    domain: str
    scan_id: str
    total_paths_found: int
    top_paths: List[ScoredAttackPath]
    processing_time_seconds: float
    generated_at: datetime


class StreamingPathUpdate(BaseModel):
    type: str = "path_update"
    path_id: str
    path_name: str
    status: str
    progress: float
    message: str 

class LogoAbuseFinding(BaseModel):
    organization_id: str
    logo_id: str
    abuse_type: str
    logo_domain: str
    alert_location: str
    url: str
    ip_address: Optional[str]
    language: Optional[str]
    accuracy: Optional[float]
    sentiment: Optional[str]
    description: Optional[str]
    alert_time: Optional[datetime]
    last_seen: Optional[datetime]
    risk: Optional[str]
    status: Optional[str]


class PortfolioDomain(BaseModel):
    organization_id: str
    domain: str
    organization_type: str
    severity: str
