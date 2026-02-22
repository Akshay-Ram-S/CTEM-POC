#!/usr/bin/env python3
"""
Attack Simulation Framework
==========================

Simulates realistic attack scenarios to validate security controls and demonstrate
how CTEM and ZTA work together to detect and prevent attack chains.

This simulator focuses on cloud attack scenarios as described in the blog:
- Internet-facing EC2 with vulnerabilities
- IAM role abuse and privilege escalation
- Lateral movement and data exfiltration
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import random

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Phases of cyber attack (based on cyber kill chain)"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AttackTechnique(Enum):
    """MITRE ATT&CK techniques"""
    T1190_EXPLOIT_PUBLIC_APPLICATION = "T1190"  # Exploit Public-Facing Application
    T1078_VALID_ACCOUNTS = "T1078"              # Valid Accounts
    T1068_EXPLOITATION_PRIVILEGE_ESCALATION = "T1068"  # Exploitation for Privilege Escalation
    T1110_BRUTE_FORCE = "T1110"                # Brute Force
    T1552_UNSECURED_CREDENTIALS = "T1552"      # Unsecured Credentials
    T1083_FILE_DIRECTORY_DISCOVERY = "T1083"   # File and Directory Discovery
    T1021_REMOTE_SERVICES = "T1021"            # Remote Services
    T1530_DATA_FROM_CLOUD_STORAGE = "T1530"    # Data from Cloud Storage Object


@dataclass
class AttackStep:
    """Represents a single step in an attack sequence"""
    step_id: str
    phase: AttackPhase
    technique: AttackTechnique
    target: str
    description: str
    preconditions: List[str]
    success_criteria: List[str]
    detection_signatures: List[str]
    success_probability: float
    execution_time_seconds: int
    executed: bool = False
    successful: bool = False
    detection_triggered: bool = False
    execution_details: Optional[Dict] = None


@dataclass
class AttackScenario:
    """Represents a complete attack scenario"""
    scenario_id: str
    name: str
    description: str
    target_environment: str
    attack_steps: List[AttackStep]
    overall_success_probability: float
    estimated_duration_minutes: int
    prerequisites: List[str]
    detection_difficulty: str
    business_impact: str


class AttackSimulator:
    """
    Core attack simulation engine for testing security controls
    """
    
    def __init__(self):
        """Initialize attack simulator with proper exception handling"""
        try:
            self.attack_scenarios: List[AttackScenario] = []
            self.executed_attacks: List[Dict] = []
            self.detection_log: List[Dict] = []
            
            # Initialize attack scenarios
            self.scenarios = self._initialize_attack_scenarios()
            
            # Detection capabilities (simulate SOC/SIEM)
            self.detection_capabilities = self._initialize_detection_capabilities()
            
            logger.info("Attack Simulator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Attack Simulator: {str(e)}")
            raise
    
    def _initialize_attack_scenarios(self) -> Dict[str, AttackScenario]:
        """Initialize predefined attack scenarios"""
        try:
            scenarios = {}
            
            # Blog Scenario: Internet -> EC2 -> IAM -> S3
            blog_scenario = self._create_blog_attack_scenario()
            scenarios[blog_scenario.scenario_id] = blog_scenario
            
            # Additional scenarios
            ssh_bruteforce_scenario = self._create_ssh_bruteforce_scenario()
            scenarios[ssh_bruteforce_scenario.scenario_id] = ssh_bruteforce_scenario
            
            credential_stuffing_scenario = self._create_credential_stuffing_scenario()
            scenarios[credential_stuffing_scenario.scenario_id] = credential_stuffing_scenario
            
            return scenarios
            
        except Exception as e:
            logger.error(f"Failed to initialize attack scenarios: {str(e)}")
            return {}
    
    def _create_blog_attack_scenario(self) -> AttackScenario:
        """Create the main attack scenario from the blog"""
        try:
            steps = [
                AttackStep(
                    step_id="blog-step-1",
                    phase=AttackPhase.RECONNAISSANCE,
                    technique=AttackTechnique.T1083_FILE_DIRECTORY_DISCOVERY,
                    target="203.0.113.1",
                    description="Scan public IP for open ports and services",
                    preconditions=["Internet connectivity"],
                    success_criteria=["Identify Apache HTTP server", "Discover port 80/443 open"],
                    detection_signatures=["Port scan patterns", "Multiple connection attempts"],
                    success_probability=0.95,
                    execution_time_seconds=30
                ),
                AttackStep(
                    step_id="blog-step-2",
                    phase=AttackPhase.INITIAL_ACCESS,
                    technique=AttackTechnique.T1190_EXPLOIT_PUBLIC_APPLICATION,
                    target="i-0123456789abcdef0",
                    description="Exploit CVE-2023-1234 on Apache HTTP server",
                    preconditions=["Apache HTTP server running", "CVE-2023-1234 unpatched"],
                    success_criteria=["Remote code execution achieved", "Shell access obtained"],
                    detection_signatures=["Abnormal HTTP requests", "Exploit payload patterns"],
                    success_probability=0.85,
                    execution_time_seconds=60
                ),
                AttackStep(
                    step_id="blog-step-3",
                    phase=AttackPhase.CREDENTIAL_ACCESS,
                    technique=AttackTechnique.T1552_UNSECURED_CREDENTIALS,
                    target="EC2 metadata service",
                    description="Extract IAM role credentials from metadata service",
                    preconditions=["Shell access on EC2 instance"],
                    success_criteria=["IAM credentials obtained", "Temporary access keys retrieved"],
                    detection_signatures=["Metadata service requests", "Credential extraction patterns"],
                    success_probability=0.90,
                    execution_time_seconds=45
                ),
                AttackStep(
                    step_id="blog-step-4",
                    phase=AttackPhase.PRIVILEGE_ESCALATION,
                    technique=AttackTechnique.T1078_VALID_ACCOUNTS,
                    target="web-server-role",
                    description="Use overprivileged IAM role for AWS API access",
                    preconditions=["IAM role credentials available"],
                    success_criteria=["AWS API authentication successful", "S3 permissions validated"],
                    detection_signatures=["Unusual IAM role usage", "Cross-service API calls"],
                    success_probability=0.75,
                    execution_time_seconds=30
                ),
                AttackStep(
                    step_id="blog-step-5",
                    phase=AttackPhase.EXFILTRATION,
                    technique=AttackTechnique.T1530_DATA_FROM_CLOUD_STORAGE,
                    target="company-sensitive-data bucket",
                    description="Access and exfiltrate sensitive data from S3 bucket",
                    preconditions=["S3 access permissions", "Bucket enumeration complete"],
                    success_criteria=["Sensitive data identified", "Data successfully downloaded"],
                    detection_signatures=["Large S3 data transfers", "Unusual download patterns"],
                    success_probability=0.80,
                    execution_time_seconds=120
                )
            ]
            
            return AttackScenario(
                scenario_id="blog-ec2-iam-s3",
                name="Internet to S3 via EC2 and IAM Abuse",
                description="Attack chain from internet-facing vulnerability to data exfiltration via IAM role abuse",
                target_environment="AWS Cloud",
                attack_steps=steps,
                overall_success_probability=0.75,
                estimated_duration_minutes=6,
                prerequisites=["Unpatched EC2 instance", "Overprivileged IAM role", "S3 bucket with PII"],
                detection_difficulty="Medium",
                business_impact="High - Data breach with PII exposure"
            )
            
        except Exception as e:
            logger.error(f"Failed to create blog attack scenario: {str(e)}")
            raise
    
    def _create_ssh_bruteforce_scenario(self) -> AttackScenario:
        """Create SSH brute force attack scenario"""
        try:
            steps = [
                AttackStep(
                    step_id="ssh-step-1",
                    phase=AttackPhase.RECONNAISSANCE,
                    technique=AttackTechnique.T1083_FILE_DIRECTORY_DISCOVERY,
                    target="203.0.113.1:22",
                    description="Discover SSH service on port 22",
                    preconditions=["SSH port accessible"],
                    success_criteria=["SSH service detected", "SSH banner retrieved"],
                    detection_signatures=["Port scan on SSH"],
                    success_probability=1.0,
                    execution_time_seconds=15
                ),
                AttackStep(
                    step_id="ssh-step-2",
                    phase=AttackPhase.INITIAL_ACCESS,
                    technique=AttackTechnique.T1110_BRUTE_FORCE,
                    target="SSH authentication",
                    description="Brute force SSH credentials",
                    preconditions=["SSH service available", "Weak credentials in use"],
                    success_criteria=["Valid credentials found", "SSH authentication successful"],
                    detection_signatures=["Multiple failed login attempts", "Brute force patterns"],
                    success_probability=0.30,
                    execution_time_seconds=300
                ),
                AttackStep(
                    step_id="ssh-step-3",
                    phase=AttackPhase.PRIVILEGE_ESCALATION,
                    technique=AttackTechnique.T1068_EXPLOITATION_PRIVILEGE_ESCALATION,
                    target="Local privilege escalation",
                    description="Escalate privileges using local exploit",
                    preconditions=["SSH access obtained", "Local vulnerability present"],
                    success_criteria=["Root access achieved"],
                    detection_signatures=["Privilege escalation attempts", "Unusual process execution"],
                    success_probability=0.60,
                    execution_time_seconds=180
                )
            ]
            
            return AttackScenario(
                scenario_id="ssh-bruteforce",
                name="SSH Brute Force Attack",
                description="Brute force SSH credentials and escalate privileges",
                target_environment="Linux Server",
                attack_steps=steps,
                overall_success_probability=0.18,  # 1.0 * 0.30 * 0.60
                estimated_duration_minutes=8,
                prerequisites=["SSH exposed to internet", "Weak credentials", "Local vulnerabilities"],
                detection_difficulty="Easy",
                business_impact="Medium - System compromise"
            )
            
        except Exception as e:
            logger.error(f"Failed to create SSH brute force scenario: {str(e)}")
            raise
    
    def _create_credential_stuffing_scenario(self) -> AttackScenario:
        """Create credential stuffing attack scenario"""
        try:
            steps = [
                AttackStep(
                    step_id="creds-step-1",
                    phase=AttackPhase.INITIAL_ACCESS,
                    technique=AttackTechnique.T1078_VALID_ACCOUNTS,
                    target="User login portal",
                    description="Attempt credential stuffing using breached credentials",
                    preconditions=["Breached credential database", "User portal accessible"],
                    success_criteria=["Valid account compromised", "Authentication successful"],
                    detection_signatures=["Multiple login attempts", "Geolocation anomalies"],
                    success_probability=0.05,  # Low success rate but high volume
                    execution_time_seconds=600
                ),
                AttackStep(
                    step_id="creds-step-2",
                    phase=AttackPhase.PERSISTENCE,
                    technique=AttackTechnique.T1078_VALID_ACCOUNTS,
                    target="Account persistence",
                    description="Maintain access to compromised account",
                    preconditions=["Account access obtained"],
                    success_criteria=["Account access maintained", "MFA bypass achieved"],
                    detection_signatures=["Unusual account activity", "Login from new devices"],
                    success_probability=0.70,
                    execution_time_seconds=120
                )
            ]
            
            return AttackScenario(
                scenario_id="credential-stuffing",
                name="Credential Stuffing Attack",
                description="Use breached credentials to access user accounts",
                target_environment="Web Application",
                attack_steps=steps,
                overall_success_probability=0.035,  # 0.05 * 0.70
                estimated_duration_minutes=12,
                prerequisites=["Breached credential database", "No MFA enforcement"],
                detection_difficulty="Medium",
                business_impact="Medium - Account compromise"
            )
            
        except Exception as e:
            logger.error(f"Failed to create credential stuffing scenario: {str(e)}")
            raise
    
    def _initialize_detection_capabilities(self) -> Dict:
        """Initialize simulated detection capabilities"""
        try:
            return {
                "network_monitoring": True,
                "endpoint_detection": False,  # Will be improved by ZTA feedback
                "behavioral_analytics": False,  # Will be improved by CTEM validation
                "threat_intelligence": True,
                "siem_correlation": False,
                "detection_thresholds": {
                    "failed_logins": 5,
                    "port_scan_rate": 10,
                    "data_transfer_mb": 100,
                    "api_calls_per_minute": 50
                },
                "response_time_seconds": 300,  # 5 minutes average response time
                "false_positive_rate": 0.15
            }
        except Exception as e:
            logger.error(f"Failed to initialize detection capabilities: {str(e)}")
            return {}

    async def simulate_cloud_attack_chain(self, environment: Dict) -> Dict:
        """
        Simulate the main cloud attack chain from the blog
        """
        try:
            logger.info("⚔️ Simulating Cloud Attack Chain: Internet -> EC2 -> IAM -> S3")
            
            scenario = self.scenarios["blog-ec2-iam-s3"]
            
            # Execute attack scenario step by step
            attack_results = await self._execute_attack_scenario(scenario, environment)
            
            # Analyze attack success and detection
            analysis = self._analyze_attack_results(attack_results, scenario)
            
            # Generate attack report
            attack_report = self._generate_attack_report(attack_results, analysis, scenario)
            
            # Store execution results
            self.executed_attacks.append(attack_report)
            
            logger.info(f"Cloud attack simulation completed: Success rate {analysis['success_rate']:.1%}")
            return attack_report
            
        except Exception as e:
            logger.error(f"Cloud attack chain simulation failed: {str(e)}")
            raise
    
    async def _execute_attack_scenario(self, scenario: AttackScenario, environment: Dict) -> Dict:
        """Execute a complete attack scenario"""
        try:
            execution_results = {
                "scenario_id": scenario.scenario_id,
                "start_time": datetime.now(),
                "step_results": [],
                "overall_success": False,
                "detection_events": [],
                "compromised_assets": []
            }
            
            logger.info(f"Executing attack scenario: {scenario.name}")
            
            # Execute each step in sequence
            attack_context = {"compromised_assets": set(), "acquired_credentials": {}}
            
            for step in scenario.attack_steps:
                logger.info(f"Executing step: {step.description}")
                
                # Check if preconditions are met
                if not self._check_preconditions(step, attack_context, environment):
                    logger.warning(f"Step {step.step_id} preconditions not met")
                    step.executed = False
                    step.successful = False
                    break
                
                # Execute the attack step
                step_result = await self._execute_attack_step(step, attack_context, environment)
                execution_results["step_results"].append(step_result)
                
                # Update attack context
                if step_result["successful"]:
                    attack_context["compromised_assets"].add(step.target)
                    if step.phase == AttackPhase.CREDENTIAL_ACCESS:
                        attack_context["acquired_credentials"][step.target] = step_result.get("credentials")
                
                # Check for detection
                detection_result = await self._check_detection(step, step_result)
                if detection_result["detected"]:
                    execution_results["detection_events"].append(detection_result)
                    step.detection_triggered = True
                
                # Simulate execution time
                await asyncio.sleep(0.1)  # Simulate processing time
            
            # Determine overall success
            successful_steps = len([r for r in execution_results["step_results"] if r["successful"]])
            execution_results["overall_success"] = successful_steps == len(scenario.attack_steps)
            execution_results["compromised_assets"] = list(attack_context["compromised_assets"])
            execution_results["end_time"] = datetime.now()
            
            return execution_results
            
        except Exception as e:
            logger.error(f"Failed to execute attack scenario: {str(e)}")
            raise
    
    def _check_preconditions(self, step: AttackStep, attack_context: Dict, environment: Dict) -> bool:
        """Check if attack step preconditions are met"""
        try:
            for precondition in step.preconditions:
                if "Shell access" in precondition:
                    # Check if we have shell access from previous steps
                    if not any("shell" in asset.lower() for asset in attack_context["compromised_assets"]):
                        return False
                
                elif "IAM credentials" in precondition or "IAM role credentials" in precondition:
                    # Check if we have IAM credentials
                    if "acquired_credentials" not in attack_context:
                        return False
                
                elif "Internet connectivity" in precondition:
                    # Always assume internet connectivity in our simulation
                    pass
                
                elif "Apache HTTP server" in precondition:
                    # Check if target has Apache running
                    for instance in environment.get("aws_resources", {}).get("ec2_instances", []):
                        if "apache" in instance.get("services", []):
                            return True
                    return False
                
                elif "unpatched" in precondition.lower():
                    # Check for vulnerabilities
                    for instance in environment.get("aws_resources", {}).get("ec2_instances", []):
                        if instance.get("vulnerabilities"):
                            return True
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check preconditions: {str(e)}")
            return False
    
    async def _execute_attack_step(self, step: AttackStep, attack_context: Dict, environment: Dict) -> Dict:
        """Execute a single attack step"""
        try:
            await asyncio.sleep(step.execution_time_seconds * 0.01)  # Simulate execution time (scaled)
            
            # Determine success based on probability
            success = random.random() < step.success_probability
            
            step.executed = True
            step.successful = success
            
            # Generate step-specific results
            step_result = {
                "step_id": step.step_id,
                "executed": True,
                "successful": success,
                "execution_time": step.execution_time_seconds,
                "technique": step.technique.value,
                "target": step.target,
                "timestamp": datetime.now().isoformat()
            }
            
            # Add step-specific execution details
            if success:
                if step.technique == AttackTechnique.T1190_EXPLOIT_PUBLIC_APPLICATION:
                    step_result["execution_details"] = {
                        "exploit_used": "CVE-2023-1234",
                        "shell_obtained": True,
                        "privileges": "www-data"
                    }
                    attack_context["compromised_assets"].add("shell-access")
                
                elif step.technique == AttackTechnique.T1552_UNSECURED_CREDENTIALS:
                    step_result["execution_details"] = {
                        "credentials_type": "IAM temporary credentials",
                        "access_key": "ASIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16)),
                        "role_name": "web-server-role"
                    }
                    step_result["credentials"] = step_result["execution_details"]
                
                elif step.technique == AttackTechnique.T1530_DATA_FROM_CLOUD_STORAGE:
                    step_result["execution_details"] = {
                        "data_accessed": True,
                        "files_downloaded": random.randint(50, 200),
                        "data_size_mb": random.randint(100, 500),
                        "pii_records": random.randint(1000, 5000)
                    }
                
                elif step.technique == AttackTechnique.T1110_BRUTE_FORCE:
                    step_result["execution_details"] = {
                        "attempts_made": random.randint(100, 1000),
                        "credentials_found": "admin:password123",
                        "login_successful": True
                    }
            
            step.execution_details = step_result.get("execution_details", {})
            return step_result
            
        except Exception as e:
            logger.error(f"Failed to execute attack step: {str(e)}")
            return {"step_id": step.step_id, "executed": False, "successful": False, "error": str(e)}
    
    async def _check_detection(self, step: AttackStep, step_result: Dict) -> Dict:
        """Check if attack step was detected by security controls"""
        try:
            await asyncio.sleep(0.05)  # Simulate detection processing time
            
            # Base detection probability based on step type
            base_detection_probability = {
                AttackTechnique.T1190_EXPLOIT_PUBLIC_APPLICATION: 0.3,
                AttackTechnique.T1552_UNSECURED_CREDENTIALS: 0.2,
                AttackTechnique.T1530_DATA_FROM_CLOUD_STORAGE: 0.6,
                AttackTechnique.T1110_BRUTE_FORCE: 0.8,
                AttackTechnique.T1078_VALID_ACCOUNTS: 0.1
            }.get(step.technique, 0.4)
            
            # Modify detection probability based on capabilities
            detection_probability = base_detection_probability
            
            if self.detection_capabilities.get("behavioral_analytics", False):
                detection_probability += 0.2
            
            if self.detection_capabilities.get("endpoint_detection", False):
                detection_probability += 0.15
            
            if self.detection_capabilities.get("siem_correlation", False):
                detection_probability += 0.25
            
            # Account for false positives
            false_positive_rate = self.detection_capabilities.get("false_positive_rate", 0.15)
            
            detected = random.random() < min(0.95, detection_probability)
            
            detection_result = {
                "step_id": step.step_id,
                "detected": detected,
                "detection_time": datetime.now() + timedelta(
                    seconds=random.randint(30, self.detection_capabilities.get("response_time_seconds", 300))
                ),
                "detection_method": self._determine_detection_method(step.technique),
                "confidence": random.uniform(0.6, 0.95) if detected else 0.0,
                "false_positive": random.random() < false_positive_rate if detected else False
            }
            
            if detected:
                logger.warning(f"Attack step detected: {step.description}")
                self.detection_log.append(detection_result)
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Failed to check detection: {str(e)}")
            return {"step_id": step.step_id, "detected": False, "error": str(e)}
    
    def _determine_detection_method(self, technique: AttackTechnique) -> str:
        """Determine which detection method would identify this technique"""
        detection_methods = {
            AttackTechnique.T1190_EXPLOIT_PUBLIC_APPLICATION: "Web Application Firewall",
            AttackTechnique.T1552_UNSECURED_CREDENTIALS: "Cloud Trail Logs",
            AttackTechnique.T1530_DATA_FROM_CLOUD_STORAGE: "Data Loss Prevention",
            AttackTechnique.T1110_BRUTE_FORCE: "Failed Login Monitoring",
            AttackTechnique.T1078_VALID_ACCOUNTS: "Behavioral Analytics"
        }
        return detection_methods.get(technique, "SIEM Correlation")
    
    def _analyze_attack_results(self, attack_results: Dict, scenario: AttackScenario) -> Dict:
        """Analyze attack execution results"""
        try:
            total_steps = len(scenario.attack_steps)
            successful_steps = len([r for r in attack_results["step_results"] if r["successful"]])
            detected_steps = len([e for e in attack_results["detection_events"] if e["detected"]])
            
            analysis = {
                "success_rate": successful_steps / total_steps if total_steps > 0 else 0,
                "detection_rate": detected_steps / total_steps if total_steps > 0 else 0,
                "attack_progression": {
                    "phases_completed": len(set(step.phase.value for step in scenario.attack_steps if step.successful)),
                    "critical_assets_compromised": len(attack_results["compromised_assets"]),
                    "credentials_stolen": any("credentials" in r for r in attack_results["step_results"])
                },
                "security_effectiveness": {
                    "prevention_score": 1 - (successful_steps / total_steps) if total_steps > 0 else 1,
                    "detection_score": detected_steps / successful_steps if successful_steps > 0 else 0,
                    "response_time_avg": sum(
                        (e["detection_time"] - attack_results["start_time"]).total_seconds() 
                        for e in attack_results["detection_events"] if e["detected"]
                    ) / max(detected_steps, 1)
                },
                "business_impact": self._assess_business_impact(attack_results, scenario)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze attack results: {str(e)}")
            return {}
    
    def _assess_business_impact(self, attack_results: Dict, scenario: AttackScenario) -> Dict:
        """Assess the business impact of the attack"""
        try:
            impact_score = 0
            impact_details = []
            
            # Check if sensitive data was accessed
            for result in attack_results["step_results"]:
                if result.get("successful") and "s3" in result.get("target", "").lower():
                    impact_score += 8
                    impact_details.append("Sensitive data potentially compromised")
                
                if result.get("successful") and "credential" in result.get("technique", "").lower():
                    impact_score += 6
                    impact_details.append("Credentials stolen")
                
                if result.get("successful") and "privilege" in result.get("step_id", "").lower():
                    impact_score += 5
                    impact_details.append("System privileges escalated")
            
            # Determine impact level
            if impact_score >= 15:
                impact_level = "Critical"
            elif impact_score >= 10:
                impact_level = "High"
            elif impact_score >= 5:
                impact_level = "Medium"
            else:
                impact_level = "Low"
            
            return {
                "impact_level": impact_level,
                "impact_score": impact_score,
                "impact_details": impact_details,
                "estimated_cost_usd": impact_score * 10000,  # Rough estimate
                "compliance_violation": impact_score >= 10
            }
            
        except Exception as e:
            logger.error(f"Failed to assess business impact: {str(e)}")
            return {"impact_level": "Unknown", "impact_score": 0}
    
    def _generate_attack_report(self, attack_results: Dict, analysis: Dict, scenario: AttackScenario) -> Dict:
        """Generate comprehensive attack simulation report"""
        try:
            return {
                "report_id": f"attack-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "scenario": {
                    "id": scenario.scenario_id,
                    "name": scenario.name,
                    "description": scenario.description
                },
                "execution": {
                    "start_time": attack_results["start_time"].isoformat(),
                    "end_time": attack_results["end_time"].isoformat(),
                    "duration_seconds": (attack_results["end_time"] - attack_results["start_time"]).total_seconds(),
                    "overall_success": attack_results["overall_success"],
                    "steps_executed": len(attack_results["step_results"]),
                    "successful_steps": len([r for r in attack_results["step_results"] if r["successful"]])
                },
                "analysis": analysis,
                "detection": {
                    "events_triggered": len(attack_results["detection_events"]),
                    "detection_details": attack_results["detection_events"],
                    "mean_detection_time": analysis["security_effectiveness"]["response_time_avg"]
                },
                "recommendations": self._generate_attack_recommendations(analysis, scenario),
                "compromised_assets": attack_results["compromised_assets"]
            }
            
        except Exception as e:
            logger.error(f"Failed to generate attack report: {str(e)}")
            return {"error": str(e)}
    
    def _generate_attack_recommendations(self, analysis: Dict, scenario: AttackScenario) -> List[str]:
        """Generate security recommendations based on attack results"""
        try:
            recommendations = []
            
            # Based on success rate
            if analysis["success_rate"] > 0.7:
                recommendations.append("Critical: Implement additional preventive controls")
                recommendations.append("Review and strengthen access controls")
            
            # Based on detection rate  
            if analysis["detection_rate"] < 0.5:
                recommendations.append("Enhance threat detection capabilities")
                recommendations.append("Deploy behavioral analytics and SIEM correlation")
            
            # Based on business impact
            business_impact = analysis.get("business_impact", {})
            if business_impact.get("impact_level") in ["Critical", "High"]:
                recommendations.append("Implement data loss prevention controls")
                recommendations.append("Review IAM permissions and apply least privilege")
            
            # Scenario-specific recommendations
            if scenario.scenario_id == "blog-ec2-iam-s3":
                recommendations.extend([
                    "Patch vulnerable EC2 instances immediately",
                    "Restrict IAM role permissions to minimum required",
                    "Enable S3 bucket access logging and monitoring",
                    "Implement network segmentation between tiers"
                ])
            
            elif scenario.scenario_id == "ssh-bruteforce":
                recommendations.extend([
                    "Implement SSH key-based authentication",
                    "Deploy fail2ban or similar brute force protection",
                    "Restrict SSH access to trusted IP ranges",
                    "Enable comprehensive audit logging"
                ])
            
            # General recommendations
            recommendations.extend([
                "Implement Zero Trust network architecture",
                "Deploy continuous threat exposure management",
                "Regular security assessments and penetration testing"
            ])
            
            return list(set(recommendations))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Failed to generate attack recommendations: {str(e)}")
            return ["Review security posture and implement defense-in-depth strategy"]

    def get_attack_summary(self) -> Dict:
        """Get summary of all attack simulations executed"""
        try:
            return {
                "total_attacks_simulated": len(self.executed_attacks),
                "successful_attacks": len([a for a in self.executed_attacks if a.get("execution", {}).get("overall_success")]),
                "detection_events": len(self.detection_log),
                "scenarios_available": len(self.scenarios),
                "average_success_rate": sum(
                    a.get("analysis", {}).get("success_rate", 0) for a in self.executed_attacks
                ) / max(len(self.executed_attacks), 1),
                "average_detection_rate": sum(
                    a.get("analysis", {}).get("detection_rate", 0) for a in self.executed_attacks
                ) / max(len(self.executed_attacks), 1)
            }
        except Exception as e:
            logger.error(f"Failed to generate attack summary: {str(e)}")
            return {}
