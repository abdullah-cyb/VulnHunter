"""Data models for VulnHunter engine using Pydantic v2."""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POTENTIAL = "POTENTIAL"
    NOT_VERIFIED = "NOT VERIFIED"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanMode(str, Enum):
    PASSIVE = "PASSIVE"
    STANDARD = "STANDARD"
    DEEP = "DEEP"

class TargetConfig(BaseModel):
    raw_target: str
    host: str
    ip_addresses: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=lambda: [21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017])
    scheme: str = "http"
    is_authorized: bool = False
    scan_mode: ScanMode = ScanMode.STANDARD
    timeout: float = 10.0
    user_agent: str = "Abdullah.Cyb-VulnHunter/1.0.0 (Authorized Security Assessment)"
    threads: int = 10

class ServiceInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: str
    product: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    extra_info: Dict[str, Any] = Field(default_factory=dict)

class TechFingerprint(BaseModel):
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    category: str = "General"
    confidence: float = 1.0
    evidence: str
    cpe: Optional[str] = None

class CVEItem(BaseModel):
    cve_id: str
    description: str
    cvss_v3_score: float = 0.0
    cvss_v3_vector: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO
    cisa_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_action: Optional[str] = None
    affected_cpes: List[str] = Field(default_factory=list)
    affected_versions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    cwe: Optional[str] = None

class ExploitInfo(BaseModel):
    mechanism: str
    prerequisites: str
    impact: str
    safe_verification_procedure: str
    remediation: str
    official_references: List[str] = Field(default_factory=list)

class FindingReasoning(BaseModel):
    what_is_it: str
    why_detected: str
    evidence_supporting: str
    confidence_explanation: str
    impact_assessment: str
    verification_guide: str
    remediation_steps: str
    references: List[str] = Field(default_factory=list)

class CorrelationMetrics(BaseModel):
    vendor_match: bool = False
    product_match: bool = False
    version_match: bool = False
    platform_match: bool = False
    exposure_detected: bool = False
    cve_severity: SeverityLevel = SeverityLevel.INFO
    kev_status: bool = False
    evidence_confidence: float = 0.0

class Finding(BaseModel):
    id: str
    cve_id: Optional[str] = None
    title: str
    category: str
    severity: SeverityLevel
    status: FindingStatus
    confidence_score: float  # 0.0 to 1.0
    target: str
    endpoint: str = "/"
    vector: str = "Network/HTTP"
    metrics: CorrelationMetrics
    reasoning: FindingReasoning
    exploit_info: Optional[ExploitInfo] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"

class StageInfo(BaseModel):
    number: int
    name: str
    status: StageStatus = StageStatus.PENDING
    details: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None

class ScanReport(BaseModel):
    scan_id: str
    brand: str = "ABDULLAH.CYB"
    product: str = "VULNHUNTER"
    tagline: str = "DISCOVER. CORRELATE. VERIFY. REPORT."
    target: str
    start_time: str
    end_time: str
    duration_seconds: float
    scan_mode: ScanMode
    authorized: bool
    stages_executed: List[StageInfo] = Field(default_factory=list)
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    open_services: List[ServiceInfo] = Field(default_factory=list)
    technologies: List[TechFingerprint] = Field(default_factory=list)
    crawled_endpoints: List[str] = Field(default_factory=list)
    discovered_params: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary_by_severity: Dict[str, int] = Field(default_factory=dict)
    summary_by_status: Dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
