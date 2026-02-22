#!/usr/bin/env python3
"""
Continuous Threat Exposure Management (CTEM) Engine
==================================================

Implements the 5-stage CTEM process:
1. Scoping - Define mission and identify critical assets
2. Discovery - Full inventory and vulnerability identification  
3. Prioritization - Rank exposures by exploitability
4. Validation - Simulate attacks to test defense effectiveness
5. Remediation - Fix gaps with context-specific actions

This implementation focuses on cloud environments (AWS) as described in the blog.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum
import hashlib
import random

logger = logging.getLogger(__name__)


class RiskSeverity(Enum):
    """Risk severity levels for prioritization"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExposureType(Enum):
    """Types of security exposures"""
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    OVERPRIVILEGED_ACCESS = "overprivileged_access"
    NETWORK_EXPOSURE = "network_exposure"
    DATA_EXPOSURE = "data_exposure"


@dataclass
class SecurityExposure:
    """Represents a security exposure discovered during CTEM process"""
    id: str
    type: ExposureType
    title: str
    description: str
    affected_assets: List[str]
    severity: RiskSeverity
    exploitability_score: float  # 0.0 - 1.0
    impact_score: float  # 0.0 - 1.0
    attack_vector: str
    attack_complexity: str
    remediation_effort: str
    discovered_at: datetime
    validated: bool = False
    remediated: bool = False
    
    def __post_init__(self):
        """Calculate composite risk score"""
        self.risk_score = (self.exploitability_score * 0.6) + (self.impact_score * 0.4)


@dataclass
class AttackPath:
    """Represents a potential attack path through the environment"""
    id: str
    start_asset: str
    target_asset: str
    steps: List[str]
    exploits_used: List[str]
    permissions_abused: List[str]
    success_probability: float
    impact: str
    detection_difficulty: float


class CTEMEngine:
    """
    Core CTEM engine implementing the 5-stage continuous threat exposure management process
    """
    
    def __init__(self):
        """Initialize CTEM engine with proper exception handling"""
        try:
            self.exposures: List[SecurityExposure] = []
            self.attack_paths: List[AttackPath] = []
            self.critical_assets: Set[str] = set()
            self.scoped_environment: Dict = {}
            self.discovery_data: Dict = {}
            
            # Vulnerability database (simplified for POC)
            self.vuln_db = self._initialize_vulnerability_database()
            
            # Attack techniques database
            self.attack_techniques = self._initialize_attack_techniques()
            
            logger.info("CTEM Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize CTEM Engine: {str(e)}")
            raise
    
    def _initialize_vulnerability_database(self) -> Dict:
        """Initialize vulnerability database for the POC"""
        try:
            return {
                "CVE-2023-1234": {
                    "description": "Remote Code Execution in Apache HTTP Server",
                    "cvss_score": 8.1,
                    "exploitability": 0.85,
                    "impact": 0.90,
                    "exploit_available": True,
                    "attack_vector": "Network",
                    "attack_complexity": "Low"
                },
                "CVE-2023-5678": {
                    "description": "Privilege Escalation in Linux Kernel", 
                    "cvss_score": 7.2,
                    "exploitability": 0.60,
                    "impact": 0.85,
                    "exploit_available": False,
                    "attack_vector": "Local",
                    "attack_complexity": "High"
                }
            }
        except Exception as e:
            logger.error(f"Failed to initialize vulnerability database: {str(e)}")
            return {}
    
    def _initialize_attack_techniques(self) -> Dict:
        """Initialize MITRE ATT&CK techniques for attack path modeling"""
        try:
            return {
                "T1190": {  # Exploit Public-Facing Application
                    "name": "Exploit Public-Facing Application",
                    "description": "Initial access through internet-facing vulnerabilities",
                    "success_rate": 0.7,
                    "detection_rate": 0.3
                },
                "T1078": {  # Valid Accounts
                    "name": "Valid Accounts",
                    "description": "Use compromised credentials for access",
                    "success_rate": 0.9,
                    "detection_rate": 0.2
                },
                "T1068": {  # Exploitation for Privilege Escalation
                    "name": "Exploitation for Privilege Escalation",
                    "description": "Exploit vulnerabilities to gain higher privileges",
                    "success_rate": 0.6,
                    "detection_rate": 0.4
                }
            }
        except Exception as e:
            logger.error(f"Failed to initialize attack techniques: {str(e)}")
            return {}
    
    async def scoping_stage(self, environment: Dict) -> Dict:
        """
        Stage 1: Scoping - Define mission and identify critical assets
        """
        try:
            logger.info("🎯 CTEM Stage 1: SCOPING - Defining critical assets and attack surface")
            
            # Identify critical assets based on business impact
            critical_assets = self._identify_critical_assets(environment)
            self.critical_assets.update(critical_assets)
            
            # Map attack surface across cloud environment
            attack_surface = self._map_attack_surface(environment)
            
            # Define scope boundaries
            scope_boundaries = self._define_scope_boundaries(environment)
            
            # Store scoped environment for later stages
            self.scoped_environment = {
                "environment": environment,
                "critical_assets": list(critical_assets),
                "attack_surface": attack_surface,
                "scope_boundaries": scope_boundaries
            }
            
            scoping_results = {
                "stage": "scoping",
                "status": "completed",
                "critical_assets_count": len(critical_assets),
                "attack_surface_size": len(attack_surface),
                "scope_boundaries": scope_boundaries,
                "completion_time": datetime.now().isoformat()
            }
            
            logger.info(f"Scoping completed: {len(critical_assets)} critical assets identified")
            return scoping_results
            
        except Exception as e:
            logger.error(f"CTEM Scoping stage failed: {str(e)}")
            raise
    
    def _identify_critical_assets(self, environment: Dict) -> Set[str]:
        """Identify business-critical assets in the environment"""
        try:
            critical_assets = set()
            
            # Identify S3 buckets containing sensitive data
            for bucket in environment.get("aws_resources", {}).get("s3_buckets", []):
                if bucket.get("contains_pii") or "sensitive" in bucket.get("name", "").lower():
                    critical_assets.add(f"s3://{bucket['name']}")
            
            # Identify EC2 instances with public exposure
            for instance in environment.get("aws_resources", {}).get("ec2_instances", []):
                if instance.get("public_ip"):
                    critical_assets.add(f"ec2:{instance['id']}")
            
            # Identify privileged IAM roles
            for role in environment.get("aws_resources", {}).get("iam_roles", []):
                if "*" in str(role.get("permissions", [])) or role.get("overprivileged"):
                    critical_assets.add(f"iam:{role['name']}")
            
            return critical_assets
            
        except Exception as e:
            logger.error(f"Failed to identify critical assets: {str(e)}")
            return set()
    
    def _map_attack_surface(self, environment: Dict) -> List[Dict]:
        """Map the external attack surface"""
        try:
            attack_surface = []
            
            # Internet-facing EC2 instances
            for instance in environment.get("aws_resources", {}).get("ec2_instances", []):
                if instance.get("public_ip"):
                    attack_surface.append({
                        "type": "ec2_instance",
                        "asset_id": instance["id"],
                        "exposure_point": instance["public_ip"],
                        "services": instance.get("services", []),
                        "risk_level": "high"
                    })
            
            # Security group misconfigurations
            for sg in environment.get("network", {}).get("security_groups", []):
                for rule in sg.get("rules", []):
                    if rule.get("source") == "0.0.0.0/0":
                        attack_surface.append({
                            "type": "security_group_rule",
                            "asset_id": sg["id"],
                            "exposure_point": f"Port {rule['port']} open to internet",
                            "risk_level": "medium" if rule["port"] in [80, 443] else "high"
                        })
            
            return attack_surface
            
        except Exception as e:
            logger.error(f"Failed to map attack surface: {str(e)}")
            return []
    
    def _define_scope_boundaries(self, environment: Dict) -> Dict:
        """Define the scope boundaries for CTEM assessment"""
        try:
            return {
                "aws_accounts": ["123456789012"],  # Demo account
                "regions": ["us-east-1", "us-west-2"],
                "resource_types": ["ec2", "s3", "iam", "vpc"],
                "exclusions": ["test-*", "dev-*"],
                "time_boundary": {
                    "start": (datetime.now() - timedelta(days=30)).isoformat(),
                    "end": datetime.now().isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Failed to define scope boundaries: {str(e)}")
            return {}

    async def discovery_stage(self, environment: Dict) -> Dict:
        """
        Stage 2: Discovery - Full inventory and vulnerability identification
        """
        try:
            logger.info("🔍 CTEM Stage 2: DISCOVERY - Taking inventory and finding exposures")
            
            # Discover vulnerabilities
            vulnerabilities = self._discover_vulnerabilities(environment)
            
            # Discover misconfigurations
            misconfigurations = self._discover_misconfigurations(environment)
            
            # Discover overprivileged access
            access_issues = self._discover_access_issues(environment)
            
            # Consolidate all discoveries
            all_exposures = vulnerabilities + misconfigurations + access_issues
            self.exposures.extend(all_exposures)
            
            # Store discovery data
            self.discovery_data = {
                "vulnerabilities": len(vulnerabilities),
                "misconfigurations": len(misconfigurations),
                "access_issues": len(access_issues),
                "total_exposures": len(all_exposures)
            }
            
            discovery_results = {
                "stage": "discovery",
                "status": "completed",
                "exposures_found": len(all_exposures),
                "breakdown": self.discovery_data,
                "completion_time": datetime.now().isoformat()
            }
            
            logger.info(f"Discovery completed: {len(all_exposures)} exposures found")
            return discovery_results
            
        except Exception as e:
            logger.error(f"CTEM Discovery stage failed: {str(e)}")
            raise
    
    def _discover_vulnerabilities(self, environment: Dict) -> List[SecurityExposure]:
        """Discover vulnerabilities in the environment"""
        try:
            vulnerabilities = []
            
            for instance in environment.get("aws_resources", {}).get("ec2_instances", []):
                for vuln_id in instance.get("vulnerabilities", []):
                    if vuln_id in self.vuln_db:
                        vuln_data = self.vuln_db[vuln_id]
                        
                        exposure = SecurityExposure(
                            id=f"vuln-{hashlib.md5((instance['id'] + '-' + vuln_id).encode()).hexdigest()[:8]}",
                            type=ExposureType.VULNERABILITY,
                            title=f"{vuln_id}: {vuln_data['description']}",
                            description=f"Vulnerability {vuln_id} found on instance {instance['id']}",
                            affected_assets=[f"ec2:{instance['id']}"],
                            severity=self._cvss_to_severity(vuln_data['cvss_score']),
                            exploitability_score=vuln_data['exploitability'],
                            impact_score=vuln_data['impact'],
                            attack_vector=vuln_data['attack_vector'],
                            attack_complexity=vuln_data['attack_complexity'],
                            remediation_effort="Medium",
                            discovered_at=datetime.now()
                        )
                        vulnerabilities.append(exposure)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Failed to discover vulnerabilities: {str(e)}")
            return []
    
    def _discover_misconfigurations(self, environment: Dict) -> List[SecurityExposure]:
        """Discover security misconfigurations"""
        try:
            misconfigurations = []
            
            # Check for overly permissive security groups
            for sg in environment.get("network", {}).get("security_groups", []):
                for rule in sg.get("rules", []):
                    if rule.get("source") == "0.0.0.0/0" and rule.get("port") not in [80, 443]:
                        exposure = SecurityExposure(
                            id=f"misconfig-{hashlib.md5((sg['id'] + '-' + str(rule['port'])).encode()).hexdigest()[:8]}",
                            type=ExposureType.MISCONFIGURATION,
                            title=f"Overly Permissive Security Group Rule",
                            description=f"Port {rule['port']} open to 0.0.0.0/0 in {sg['id']}",
                            affected_assets=[f"sg:{sg['id']}"],
                            severity=RiskSeverity.HIGH if rule["port"] == 22 else RiskSeverity.MEDIUM,
                            exploitability_score=0.8,
                            impact_score=0.7,
                            attack_vector="Network",
                            attack_complexity="Low",
                            remediation_effort="Low",
                            discovered_at=datetime.now()
                        )
                        misconfigurations.append(exposure)
            
            # Check for unencrypted S3 buckets
            for bucket in environment.get("aws_resources", {}).get("s3_buckets", []):
                if not bucket.get("encryption", False):
                    exposure = SecurityExposure(
                        id=f"misconfig-{hashlib.md5(bucket['name'].encode()).hexdigest()[:8]}",
                        type=ExposureType.MISCONFIGURATION,
                        title="Unencrypted S3 Bucket",
                        description=f"S3 bucket {bucket['name']} is not encrypted",
                        affected_assets=[f"s3://{bucket['name']}"],
                        severity=RiskSeverity.MEDIUM,
                        exploitability_score=0.3,
                        impact_score=0.8,
                        attack_vector="Local",
                        attack_complexity="Low",
                        remediation_effort="Low",
                        discovered_at=datetime.now()
                    )
                    misconfigurations.append(exposure)
            
            return misconfigurations
            
        except Exception as e:
            logger.error(f"Failed to discover misconfigurations: {str(e)}")
            return []
    
    def _discover_access_issues(self, environment: Dict) -> List[SecurityExposure]:
        """Discover overprivileged access and identity issues"""
        try:
            access_issues = []
            
            # Check for overprivileged IAM roles
            for role in environment.get("aws_resources", {}).get("iam_roles", []):
                if role.get("overprivileged", False):
                    exposure = SecurityExposure(
                        id=f"access-{hashlib.md5(role['name'].encode()).hexdigest()[:8]}",
                        type=ExposureType.OVERPRIVILEGED_ACCESS,
                        title="Overprivileged IAM Role",
                        description=f"IAM role {role['name']} has excessive permissions",
                        affected_assets=[f"iam:{role['name']}"],
                        severity=RiskSeverity.HIGH,
                        exploitability_score=0.6,
                        impact_score=0.9,
                        attack_vector="Local",
                        attack_complexity="Low",
                        remediation_effort="Medium",
                        discovered_at=datetime.now()
                    )
                    access_issues.append(exposure)
            
            # Check for users without MFA
            for user in environment.get("users", []):
                if not user.get("mfa_enabled", False):
                    exposure = SecurityExposure(
                        id=f"access-{hashlib.md5(user['username'].encode()).hexdigest()[:8]}",
                        type=ExposureType.OVERPRIVILEGED_ACCESS,
                        title="User Without MFA",
                        description=f"User {user['username']} does not have MFA enabled",
                        affected_assets=[f"user:{user['username']}"],
                        severity=RiskSeverity.MEDIUM,
                        exploitability_score=0.7,
                        impact_score=0.6,
                        attack_vector="Network",
                        attack_complexity="Low",
                        remediation_effort="Low",
                        discovered_at=datetime.now()
                    )
                    access_issues.append(exposure)
            
            return access_issues
            
        except Exception as e:
            logger.error(f"Failed to discover access issues: {str(e)}")
            return []
    
    def _cvss_to_severity(self, cvss_score: float) -> RiskSeverity:
        """Convert CVSS score to risk severity"""
        if cvss_score >= 9.0:
            return RiskSeverity.CRITICAL
        elif cvss_score >= 7.0:
            return RiskSeverity.HIGH
        elif cvss_score >= 4.0:
            return RiskSeverity.MEDIUM
        else:
            return RiskSeverity.LOW

    async def prioritization_stage(self, discovery_results: Dict) -> Dict:
        """
        Stage 3: Prioritization - Rank exposures by exploitability and business impact
        """
        try:
            logger.info("📊 CTEM Stage 3: PRIORITIZATION - Ranking exposures by risk")
            
            # Sort exposures by risk score (exploitability + impact)
            sorted_exposures = sorted(self.exposures, key=lambda x: x.risk_score, reverse=True)
            
            # Apply business context prioritization
            business_prioritized = self._apply_business_context(sorted_exposures)
            
            # Generate priority matrix
            priority_matrix = self._generate_priority_matrix(business_prioritized)
            
            # Create remediation timeline
            remediation_timeline = self._create_remediation_timeline(business_prioritized)
            
            prioritization_results = {
                "stage": "prioritization",
                "status": "completed",
                "total_exposures": len(self.exposures),
                "critical_priority": len([e for e in business_prioritized if e.severity == RiskSeverity.CRITICAL]),
                "high_priority": len([e for e in business_prioritized if e.severity == RiskSeverity.HIGH]),
                "priority_matrix": priority_matrix,
                "remediation_timeline": remediation_timeline,
                "completion_time": datetime.now().isoformat()
            }
            
            logger.info(f"Prioritization completed: {len(business_prioritized)} exposures ranked")
            return prioritization_results
            
        except Exception as e:
            logger.error(f"CTEM Prioritization stage failed: {str(e)}")
            raise
    
    def _apply_business_context(self, exposures: List[SecurityExposure]) -> List[SecurityExposure]:
        """Apply business context to prioritize exposures"""
        try:
            # Boost priority for exposures affecting critical assets
            for exposure in exposures:
                for asset in exposure.affected_assets:
                    if asset in self.critical_assets:
                        # Increase risk score for critical assets
                        exposure.risk_score = min(1.0, exposure.risk_score * 1.3)
                        break
            
            # Re-sort after business context adjustment
            return sorted(exposures, key=lambda x: x.risk_score, reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to apply business context: {str(e)}")
            return exposures
    
    def _generate_priority_matrix(self, exposures: List[SecurityExposure]) -> Dict:
        """Generate a priority matrix for visualization"""
        try:
            matrix = {
                "critical_high_exploitability": [],
                "critical_low_exploitability": [],
                "high_high_exploitability": [],
                "high_low_exploitability": [],
                "other": []
            }
            
            for exposure in exposures:
                high_exploitability = exposure.exploitability_score > 0.7
                
                if exposure.severity == RiskSeverity.CRITICAL:
                    if high_exploitability:
                        matrix["critical_high_exploitability"].append(exposure.id)
                    else:
                        matrix["critical_low_exploitability"].append(exposure.id)
                elif exposure.severity == RiskSeverity.HIGH:
                    if high_exploitability:
                        matrix["high_high_exploitability"].append(exposure.id)
                    else:
                        matrix["high_low_exploitability"].append(exposure.id)
                else:
                    matrix["other"].append(exposure.id)
            
            return matrix
            
        except Exception as e:
            logger.error(f"Failed to generate priority matrix: {str(e)}")
            return {}
    
    def _create_remediation_timeline(self, exposures: List[SecurityExposure]) -> Dict:
        """Create a timeline for remediation activities"""
        try:
            timeline = {
                "immediate": [],  # 0-24 hours
                "short_term": [],  # 1-7 days
                "medium_term": [],  # 1-4 weeks
                "long_term": []  # 1+ months
            }
            
            for exposure in exposures:
                if (exposure.severity == RiskSeverity.CRITICAL and 
                    exposure.exploitability_score > 0.8):
                    timeline["immediate"].append(exposure.id)
                elif exposure.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH]:
                    timeline["short_term"].append(exposure.id)
                elif exposure.severity == RiskSeverity.MEDIUM:
                    timeline["medium_term"].append(exposure.id)
                else:
                    timeline["long_term"].append(exposure.id)
            
            return timeline
            
        except Exception as e:
            logger.error(f"Failed to create remediation timeline: {str(e)}")
            return {}

    async def validation_stage(self, prioritization_results: Dict) -> Dict:
        """
        Stage 4: Validation - Simulate attacks to test exploitability
        """
        try:
            logger.info("🎯 CTEM Stage 4: VALIDATION - Simulating attacks to test defenses")
            
            # Generate attack paths
            attack_paths = await self._generate_attack_paths()
            
            # Simulate exploit attempts
            exploitation_results = await self._simulate_exploits()
            
            # Test lateral movement possibilities
            lateral_movement = await self._test_lateral_movement()
            
            # Validate defense effectiveness
            defense_effectiveness = await self._validate_defenses()
            
            # Mark exposures as validated
            validated_count = self._mark_validated_exposures(exploitation_results)
            
            validation_results = {
                "stage": "validation",
                "status": "completed",
                "attack_paths_found": len(attack_paths),
                "successful_exploits": len(exploitation_results["successful"]),
                "failed_exploits": len(exploitation_results["failed"]),
                "lateral_movement_possible": lateral_movement["possible"],
                "defense_effectiveness": defense_effectiveness["overall_score"],
                "validated_exposures": validated_count,
                "completion_time": datetime.now().isoformat()
            }
            
            logger.info(f"Validation completed: {len(attack_paths)} attack paths analyzed")
            return validation_results
            
        except Exception as e:
            logger.error(f"CTEM Validation stage failed: {str(e)}")
            raise
    
    async def _generate_attack_paths(self) -> List[AttackPath]:
        """Generate realistic attack paths through the environment"""
        try:
            attack_paths = []
            
            # Simulate the blog scenario: Internet -> EC2 -> IAM -> S3
            blog_scenario_path = AttackPath(
                id="path-internet-to-s3",
                start_asset="internet",
                target_asset="s3://company-sensitive-data",
                steps=[
                    "1. Exploit CVE-2023-1234 on public EC2 instance",
                    "2. Gain shell access on i-0123456789abcdef0",
                    "3. Extract IAM role credentials from metadata service",
                    "4. Use overprivileged web-server-role for S3 access",
                    "5. Access sensitive data in S3 bucket"
                ],
                exploits_used=["CVE-2023-1234"],
                permissions_abused=["web-server-role"],
                success_probability=0.75,
                impact="Data exfiltration of PII",
                detection_difficulty=0.3
            )
            attack_paths.append(blog_scenario_path)
            self.attack_paths.append(blog_scenario_path)
            
            # Additional attack path: SSH brute force
            ssh_path = AttackPath(
                id="path-ssh-bruteforce",
                start_asset="internet",
                target_asset="ec2:i-0123456789abcdef0",
                steps=[
                    "1. Port scan reveals SSH on port 22",
                    "2. Brute force SSH credentials", 
                    "3. Gain shell access",
                    "4. Privilege escalation via local exploit"
                ],
                exploits_used=["SSH-BRUTEFORCE", "CVE-2023-5678"],
                permissions_abused=["local-admin"],
                success_probability=0.45,
                impact="System compromise",
                detection_difficulty=0.6
            )
            attack_paths.append(ssh_path)
            self.attack_paths.append(ssh_path)
            
            return attack_paths
            
        except Exception as e:
            logger.error(f"Failed to generate attack paths: {str(e)}")
            return []
    
    async def _simulate_exploits(self) -> Dict:
        """Simulate exploitation of discovered vulnerabilities"""
        try:
            await asyncio.sleep(0.1)  # Simulate processing time
            
            successful_exploits = []
            failed_exploits = []
            
            for exposure in self.exposures:
                if exposure.type == ExposureType.VULNERABILITY:
                    # Simulate exploit attempt based on exploitability score
                    if random.random() < exposure.exploitability_score:
                        successful_exploits.append({
                            "exposure_id": exposure.id,
                            "technique": "T1190",  # Exploit Public-Facing Application
                            "success_probability": exposure.exploitability_score,
                            "impact": exposure.impact_score
                        })
                        exposure.validated = True
                    else:
                        failed_exploits.append({
                            "exposure_id": exposure.id,
                            "failure_reason": "Exploit failed or mitigated"
                        })
            
            return {
                "successful": successful_exploits,
                "failed": failed_exploits
            }
            
        except Exception as e:
            logger.error(f"Failed to simulate exploits: {str(e)}")
            return {"successful": [], "failed": []}
    
    async def _test_lateral_movement(self) -> Dict:
        """Test possibilities for lateral movement"""
        try:
            await asyncio.sleep(0.1)  # Simulate processing time
            
            # Analyze network connectivity and permissions
            lateral_paths = []
            
            # Check if compromised EC2 can access other resources
            for path in self.attack_paths:
                if "IAM" in " ".join(path.steps):
                    lateral_paths.append({
                        "from": path.start_asset,
                        "to": path.target_asset,
                        "method": "IAM role abuse",
                        "success_rate": path.success_probability
                    })
            
            return {
                "possible": len(lateral_paths) > 0,
                "paths": lateral_paths,
                "risk_level": "high" if lateral_paths else "low"
            }
            
        except Exception as e:
            logger.error(f"Failed to test lateral movement: {str(e)}")
            return {"possible": False, "paths": [], "risk_level": "unknown"}
    
    async def _validate_defenses(self) -> Dict:
        """Validate effectiveness of existing security controls"""
        try:
            await asyncio.sleep(0.1)  # Simulate processing time
            
            # Simulate defense evaluation
            defense_scores = {
                "network_segmentation": 0.6,  # Some segmentation but not complete
                "access_controls": 0.4,       # Basic controls but overprivileged roles
                "monitoring": 0.5,            # Some logging but limited detection
                "vulnerability_management": 0.3  # Patching gaps exist
            }
            
            overall_score = sum(defense_scores.values()) / len(defense_scores)
            
            return {
                "overall_score": overall_score,
                "component_scores": defense_scores,
                "recommendations": [
                    "Implement least privilege access controls",
                    "Enhance network microsegmentation", 
                    "Improve vulnerability patching cadence",
                    "Deploy behavioral monitoring"
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to validate defenses: {str(e)}")
            return {"overall_score": 0.0, "component_scores": {}, "recommendations": []}
    
    def _mark_validated_exposures(self, exploitation_results: Dict) -> int:
        """Mark exposures as validated based on exploitation results"""
        try:
            validated_count = 0
            
            # Mark successful exploits as validated
            for exploit in exploitation_results.get("successful", []):
                exposure_id = exploit["exposure_id"]
                for exposure in self.exposures:
                    if exposure.id == exposure_id:
                        exposure.validated = True
                        validated_count += 1
                        break
            
            return validated_count
            
        except Exception as e:
            logger.error(f"Failed to mark validated exposures: {str(e)}")
            return 0

    async def remediation_stage(self, validation_results: Dict) -> Dict:
        """
        Stage 5: Remediation - Fix gaps with context-specific actions
        """
        try:
            logger.info("🔧 CTEM Stage 5: REMEDIATION - Implementing fixes for validated exposures")
            
            # Generate remediation plans
            remediation_plans = self._generate_remediation_plans()
            
            # Simulate remediation actions
            remediation_results = await self._execute_remediations(remediation_plans)
            
            # Update exposure status
            remediated_count = self._update_remediation_status(remediation_results)
            
            # Calculate risk reduction
            risk_reduction = self._calculate_risk_reduction()
            
            remediation_stage_results = {
                "stage": "remediation",
                "status": "completed",
                "remediation_plans_created": len(remediation_plans),
                "successful_remediations": remediation_results["successful"],
                "failed_remediations": remediation_results["failed"],
                "exposures_remediated": remediated_count,
                "risk_reduction_percentage": risk_reduction,
                "completion_time": datetime.now().isoformat()
            }
            
            logger.info(f"Remediation completed: {remediated_count} exposures remediated")
            return remediation_stage_results
            
        except Exception as e:
            logger.error(f"CTEM Remediation stage failed: {str(e)}")
            raise
    
    def _generate_remediation_plans(self) -> List[Dict]:
        """Generate remediation plans for validated exposures"""
        try:
            plans = []
            
            # Generate plans for critical and high priority exposures
            high_priority_exposures = [
                e for e in self.exposures 
                if e.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH] and e.validated
            ]
            
            for exposure in high_priority_exposures:
                if exposure.type == ExposureType.VULNERABILITY:
                    plans.append({
                        "exposure_id": exposure.id,
                        "type": "patch_vulnerability",
                        "priority": "high",
                        "actions": [
                            f"Apply security patch for {exposure.title}",
                            "Restart affected services",
                            "Verify patch effectiveness"
                        ],
                        "estimated_effort": exposure.remediation_effort,
                        "business_impact": "low"
                    })
                
                elif exposure.type == ExposureType.MISCONFIGURATION:
                    plans.append({
                        "exposure_id": exposure.id,
                        "type": "fix_configuration",
                        "priority": "medium",
                        "actions": [
                            f"Update configuration: {exposure.description}",
                            "Test configuration change",
                            "Deploy to production"
                        ],
                        "estimated_effort": exposure.remediation_effort,
                        "business_impact": "minimal"
                    })
                
                elif exposure.type == ExposureType.OVERPRIVILEGED_ACCESS:
                    plans.append({
                        "exposure_id": exposure.id,
                        "type": "reduce_privileges",
                        "priority": "high",
                        "actions": [
                            f"Review and reduce permissions for {exposure.title}",
                            "Implement least privilege access",
                            "Update IAM policies"
                        ],
                        "estimated_effort": exposure.remediation_effort,
                        "business_impact": "medium"
                    })
            
            return plans
            
        except Exception as e:
            logger.error(f"Failed to generate remediation plans: {str(e)}")
            return []
    
    async def _execute_remediations(self, plans: List[Dict]) -> Dict:
        """Simulate execution of remediation plans"""
        try:
            await asyncio.sleep(0.2)  # Simulate processing time
            
            successful = 0
            failed = 0
            
            for plan in plans:
                # Simulate success/failure based on complexity
                success_rate = {
                    "patch_vulnerability": 0.9,
                    "fix_configuration": 0.95,
                    "reduce_privileges": 0.8
                }.get(plan["type"], 0.85)
                
                if random.random() < success_rate:
                    successful += 1
                    logger.info(f"Remediation successful: {plan['exposure_id']}")
                else:
                    failed += 1
                    logger.warning(f"Remediation failed: {plan['exposure_id']}")
            
            return {
                "successful": successful,
                "failed": failed,
                "total_attempted": len(plans)
            }
            
        except Exception as e:
            logger.error(f"Failed to execute remediations: {str(e)}")
            return {"successful": 0, "failed": 0, "total_attempted": 0}
    
    def _update_remediation_status(self, remediation_results: Dict) -> int:
        """Update exposure status based on remediation results"""
        try:
            remediated_count = 0
            
            # Mark exposures as remediated (simplified logic for POC)
            high_priority_exposures = [
                e for e in self.exposures 
                if e.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH] and e.validated
            ]
            
            # Simulate remediation based on success rate
            remediations_to_apply = min(
                remediation_results["successful"],
                len(high_priority_exposures)
            )
            
            for i in range(remediations_to_apply):
                if i < len(high_priority_exposures):
                    high_priority_exposures[i].remediated = True
                    remediated_count += 1
            
            return remediated_count
            
        except Exception as e:
            logger.error(f"Failed to update remediation status: {str(e)}")
            return 0
    
    def _calculate_risk_reduction(self) -> float:
        """Calculate overall risk reduction percentage"""
        try:
            total_exposures = len(self.exposures)
            if total_exposures == 0:
                return 0.0
            
            remediated_exposures = len([e for e in self.exposures if e.remediated])
            
            # Calculate weighted risk reduction
            total_risk_before = sum(e.risk_score for e in self.exposures)
            remediated_risk = sum(e.risk_score for e in self.exposures if e.remediated)
            
            if total_risk_before == 0:
                return 0.0
            
            risk_reduction = (remediated_risk / total_risk_before) * 100
            return round(risk_reduction, 2)
            
        except Exception as e:
            logger.error(f"Failed to calculate risk reduction: {str(e)}")
            return 0.0

    def get_ctem_summary(self) -> Dict:
        """Get a summary of the CTEM process results"""
        try:
            return {
                "total_exposures": len(self.exposures),
                "critical_exposures": len([e for e in self.exposures if e.severity == RiskSeverity.CRITICAL]),
                "high_exposures": len([e for e in self.exposures if e.severity == RiskSeverity.HIGH]),
                "validated_exposures": len([e for e in self.exposures if e.validated]),
                "remediated_exposures": len([e for e in self.exposures if e.remediated]),
                "attack_paths": len(self.attack_paths),
                "critical_assets": len(self.critical_assets),
                "overall_risk_score": round(sum(e.risk_score for e in self.exposures) / max(len(self.exposures), 1), 2)
            }
        except Exception as e:
            logger.error(f"Failed to generate CTEM summary: {str(e)}")
            return {}
