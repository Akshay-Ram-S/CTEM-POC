#!/usr/bin/env python3
"""
Security Orchestrator
====================

Orchestrates the integration between CTEM and ZTA systems to demonstrate
how they work together to provide comprehensive security validation.

This orchestrator implements the feedback loop described in the blog:
- ZTA provides structured access control and policy enforcement
- CTEM validates the effectiveness of those controls through continuous testing
- Findings from each system inform and improve the other
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of CTEM-ZTA integration"""
    POLICY_FEEDBACK = "policy_feedback"
    CONTROL_VALIDATION = "control_validation"
    RISK_CORRELATION = "risk_correlation"
    REMEDIATION_GUIDANCE = "remediation_guidance"


class ValidationResult(Enum):
    """Results of security control validation"""
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    UNTESTED = "untested"


@dataclass
class IntegrationInsight:
    """Represents an insight from CTEM-ZTA integration"""
    insight_id: str
    type: IntegrationType
    source_system: str
    target_system: str
    finding: str
    recommendation: str
    priority: str
    confidence: float
    timestamp: datetime


@dataclass
class SecurityPosture:
    """Represents overall security posture from integrated view"""
    posture_score: float
    risk_level: str
    zta_maturity: float
    ctem_coverage: float
    integration_effectiveness: float
    critical_gaps: List[str]
    improvement_areas: List[str]
    last_assessment: datetime


class SecurityOrchestrator:
    """
    Orchestrates CTEM and ZTA integration to create a unified security validation platform
    """
    
    def __init__(self, ctem_engine, zta_engine):
        """Initialize security orchestrator with proper exception handling"""
        try:
            self.ctem = ctem_engine
            self.zta = zta_engine
            
            # Integration state
            self.integration_insights: List[IntegrationInsight] = []
            self.security_posture: Optional[SecurityPosture] = None
            self.feedback_history: List[Dict] = []
            
            # Integration configuration
            self.integration_config = self._initialize_integration_config()
            
            # Validation results tracking
            self.validation_results: Dict[str, ValidationResult] = {}
            
            logger.info("Security Orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Security Orchestrator: {str(e)}")
            raise
    
    def _initialize_integration_config(self) -> Dict:
        """Initialize integration configuration"""
        try:
            return {
                "feedback_loop_enabled": True,
                "continuous_validation_interval": 3600,  # 1 hour
                "risk_correlation_threshold": 0.7,
                "auto_policy_update": False,  # Require manual approval
                "validation_coverage_target": 0.8,
                "integration_metrics": {
                    "policy_updates": 0,
                    "control_validations": 0,
                    "risk_correlations": 0,
                    "remediation_actions": 0
                }
            }
        except Exception as e:
            logger.error(f"Failed to initialize integration config: {str(e)}")
            return {}

    async def run_integrated_analysis(self, environment: Dict) -> Dict:
        """
        Run integrated CTEM + ZTA analysis demonstrating the feedback loop
        """
        try:
            logger.info("🔄 Running Integrated CTEM + ZTA Analysis")
            
            # Phase 1: Run baseline assessments
            zta_baseline = await self.zta.assess_environment(environment)
            ctem_baseline = await self._run_ctem_baseline(environment)
            
            # Phase 2: Cross-validate findings
            cross_validation = await self._cross_validate_findings(
                ctem_baseline, zta_baseline, environment
            )
            
            # Phase 3: Generate integration insights
            insights = await self._generate_integration_insights(
                cross_validation, ctem_baseline, zta_baseline
            )
            
            # Phase 4: Apply feedback loop
            feedback_results = await self._apply_feedback_loop(insights, environment)
            
            # Phase 5: Calculate integrated risk assessment
            integrated_risk = await self._calculate_integrated_risk(
                ctem_baseline, zta_baseline, cross_validation
            )
            
            # Phase 6: Update security posture
            self.security_posture = await self._update_security_posture(
                integrated_risk, insights, feedback_results
            )
            
            analysis_results = {
                "integration_timestamp": datetime.now().isoformat(),
                "zta_baseline": zta_baseline,
                "ctem_baseline": ctem_baseline,
                "cross_validation": cross_validation,
                "integration_insights": [asdict(insight) for insight in insights],
                "feedback_loop_results": feedback_results,
                "integrated_risk_assessment": integrated_risk,
                "security_posture": asdict(self.security_posture),
                "attack_paths": self._identify_integrated_attack_paths(),
                "zta_violations": len(self.zta.zta_violations),
                "risk_score": integrated_risk["overall_risk_score"]
            }
            
            logger.info(f"Integrated analysis completed: Risk score {integrated_risk['overall_risk_score']:.2f}")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Integrated analysis failed: {str(e)}")
            raise
    
    async def _run_ctem_baseline(self, environment: Dict) -> Dict:
        """Run CTEM baseline assessment"""
        try:
            # Run all 5 CTEM stages
            scoping = await self.ctem.scoping_stage(environment)
            discovery = await self.ctem.discovery_stage(environment)
            prioritization = await self.ctem.prioritization_stage(discovery)
            validation = await self.ctem.validation_stage(prioritization)
            remediation = await self.ctem.remediation_stage(validation)
            
            return {
                "scoping": scoping,
                "discovery": discovery,
                "prioritization": prioritization,
                "validation": validation,
                "remediation": remediation,
                "ctem_summary": self.ctem.get_ctem_summary()
            }
            
        except Exception as e:
            logger.error(f"Failed to run CTEM baseline: {str(e)}")
            raise
    
    async def _cross_validate_findings(self, ctem_results: Dict, zta_results: Dict, 
                                      environment: Dict) -> Dict:
        """Cross-validate findings between CTEM and ZTA systems"""
        try:
            logger.info("🔍 Cross-validating CTEM and ZTA findings")
            
            # Find overlapping issues
            overlapping_issues = await self._find_overlapping_issues(ctem_results, zta_results)
            
            # Validate ZTA policies against CTEM attack paths
            policy_validation = await self._validate_zta_policies_against_attack_paths()
            
            # Check CTEM coverage of ZTA violations
            coverage_analysis = await self._analyze_ctem_coverage_of_zta_violations()
            
            # Identify gaps in both systems
            gap_analysis = await self._identify_system_gaps(ctem_results, zta_results)
            
            cross_validation = {
                "overlapping_issues": overlapping_issues,
                "policy_validation": policy_validation,
                "coverage_analysis": coverage_analysis,
                "gap_analysis": gap_analysis,
                "validation_confidence": self._calculate_validation_confidence(overlapping_issues)
            }
            
            logger.info(f"Cross-validation completed: {len(overlapping_issues)} overlapping issues found")
            return cross_validation
            
        except Exception as e:
            logger.error(f"Cross-validation failed: {str(e)}")
            return {}
    
    async def _find_overlapping_issues(self, ctem_results: Dict, zta_results: Dict) -> List[Dict]:
        """Find security issues identified by both CTEM and ZTA"""
        try:
            overlapping = []
            
            # Compare CTEM exposures with ZTA violations
            ctem_summary = ctem_results.get("ctem_summary", {})
            
            # Check for IAM-related issues
            if ctem_summary.get("high_exposures", 0) > 0 and zta_results.get("violations_found", 0) > 0:
                overlapping.append({
                    "issue_type": "overprivileged_access",
                    "ctem_finding": "High-risk IAM exposures detected",
                    "zta_finding": "Excessive privilege violations found",
                    "severity": "high",
                    "confidence": 0.9,
                    "correlation_strength": "strong"
                })
            
            # Check for network segmentation issues
            network_score = zta_results.get("network_segmentation", {}).get("score", 0)
            if network_score < 70:
                overlapping.append({
                    "issue_type": "network_segmentation",
                    "ctem_finding": "Attack paths through network discovered",
                    "zta_finding": f"Network segmentation score: {network_score}/100",
                    "severity": "medium",
                    "confidence": 0.8,
                    "correlation_strength": "medium"
                })
            
            # Check for authentication issues
            identity_score = zta_results.get("identity_controls", {}).get("score", 0)
            if identity_score < 80:
                overlapping.append({
                    "issue_type": "authentication_weakness",
                    "ctem_finding": "Identity-based attack vectors validated",
                    "zta_finding": f"Identity controls score: {identity_score}/100",
                    "severity": "high",
                    "confidence": 0.85,
                    "correlation_strength": "strong"
                })
            
            return overlapping
            
        except Exception as e:
            logger.error(f"Failed to find overlapping issues: {str(e)}")
            return []
    
    async def _validate_zta_policies_against_attack_paths(self) -> Dict:
        """Validate ZTA policies against CTEM-discovered attack paths"""
        try:
            validation_results = {
                "total_attack_paths": len(self.ctem.attack_paths),
                "policies_tested": 0,
                "effective_policies": 0,
                "ineffective_policies": 0,
                "policy_gaps": []
            }
            
            for attack_path in self.ctem.attack_paths:
                validation_results["policies_tested"] += 1
                
                # Simulate policy effectiveness against attack path
                if attack_path.success_probability < 0.3:
                    # Attack path has low success - policies are effective
                    validation_results["effective_policies"] += 1
                    self.validation_results[attack_path.id] = ValidationResult.EFFECTIVE
                elif attack_path.success_probability < 0.7:
                    # Partial effectiveness
                    validation_results["effective_policies"] += 0.5
                    self.validation_results[attack_path.id] = ValidationResult.PARTIALLY_EFFECTIVE
                else:
                    # Policy gap identified
                    validation_results["ineffective_policies"] += 1
                    validation_results["policy_gaps"].append({
                        "attack_path": attack_path.id,
                        "gap_description": f"No effective policy for {attack_path.impact}",
                        "recommendation": "Implement additional access controls"
                    })
                    self.validation_results[attack_path.id] = ValidationResult.INEFFECTIVE
            
            # Calculate overall effectiveness
            if validation_results["policies_tested"] > 0:
                effectiveness = (validation_results["effective_policies"] / 
                               validation_results["policies_tested"])
                validation_results["overall_effectiveness"] = effectiveness
            else:
                validation_results["overall_effectiveness"] = 0.0
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Failed to validate ZTA policies: {str(e)}")
            return {}
    
    async def _analyze_ctem_coverage_of_zta_violations(self) -> Dict:
        """Analyze how well CTEM covers ZTA-identified violations"""
        try:
            coverage_analysis = {
                "total_zta_violations": len(self.zta.zta_violations),
                "covered_by_ctem": 0,
                "uncovered_violations": [],
                "coverage_percentage": 0.0
            }
            
            for violation in self.zta.zta_violations:
                # Check if CTEM has corresponding exposure
                covered = False
                for exposure in self.ctem.exposures:
                    if self._violations_match(violation, exposure):
                        covered = True
                        coverage_analysis["covered_by_ctem"] += 1
                        break
                
                if not covered:
                    coverage_analysis["uncovered_violations"].append({
                        "violation_id": violation.id,
                        "violation_type": violation.type.value,
                        "description": violation.description,
                        "recommendation": "Extend CTEM scope to cover this violation type"
                    })
            
            if coverage_analysis["total_zta_violations"] > 0:
                coverage_analysis["coverage_percentage"] = (
                    coverage_analysis["covered_by_ctem"] / 
                    coverage_analysis["total_zta_violations"]
                )
            
            return coverage_analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze CTEM coverage: {str(e)}")
            return {}
    
    def _violations_match(self, zta_violation, ctem_exposure) -> bool:
        """Check if ZTA violation and CTEM exposure are related"""
        try:
            # Simple matching logic based on asset overlap
            zta_assets = set(zta_violation.affected_resources)
            ctem_assets = set(ctem_exposure.affected_assets)
            
            # Check for asset overlap
            if zta_assets.intersection(ctem_assets):
                return True
            
            # Check for type similarity
            type_mapping = {
                "excessive_privileges": ["overprivileged_access"],
                "poor_segmentation": ["network_exposure", "misconfiguration"],
                "implicit_trust": ["overprivileged_access"]
            }
            
            zta_type_key = zta_violation.type.value
            if zta_type_key in type_mapping:
                mapped_types = type_mapping[zta_type_key]
                if ctem_exposure.type.value in mapped_types:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to match violations: {str(e)}")
            return False
    
    async def _identify_system_gaps(self, ctem_results: Dict, zta_results: Dict) -> Dict:
        """Identify gaps in both CTEM and ZTA coverage"""
        try:
            gap_analysis = {
                "ctem_gaps": [],
                "zta_gaps": [],
                "integration_gaps": []
            }
            
            # Analyze CTEM gaps
            ctem_summary = ctem_results.get("ctem_summary", {})
            if ctem_summary.get("validated_exposures", 0) < ctem_summary.get("total_exposures", 1):
                gap_analysis["ctem_gaps"].append({
                    "gap_type": "validation_coverage",
                    "description": "Not all exposures have been validated through attack simulation",
                    "impact": "Medium",
                    "recommendation": "Extend validation coverage to include all critical exposures"
                })
            
            # Analyze ZTA gaps
            zta_maturity = zta_results.get("overall_zta_maturity", 0)
            if zta_maturity < 80:
                gap_analysis["zta_gaps"].append({
                    "gap_type": "maturity_level",
                    "description": f"ZTA maturity score is {zta_maturity}/100",
                    "impact": "High",
                    "recommendation": "Implement comprehensive Zero Trust architecture"
                })
            
            # Identify integration gaps
            if not self.integration_config.get("feedback_loop_enabled", False):
                gap_analysis["integration_gaps"].append({
                    "gap_type": "feedback_loop",
                    "description": "Automated feedback loop between CTEM and ZTA is disabled",
                    "impact": "Medium",
                    "recommendation": "Enable automated policy feedback based on CTEM findings"
                })
            
            return gap_analysis
            
        except Exception as e:
            logger.error(f"Failed to identify system gaps: {str(e)}")
            return {}
    
    def _calculate_validation_confidence(self, overlapping_issues: List[Dict]) -> float:
        """Calculate confidence in validation based on overlap"""
        try:
            if not overlapping_issues:
                return 0.5  # Neutral confidence
            
            # Calculate weighted confidence based on correlation strength
            total_confidence = 0
            weight_sum = 0
            
            for issue in overlapping_issues:
                confidence = issue.get("confidence", 0.5)
                correlation = issue.get("correlation_strength", "medium")
                
                weight = {"weak": 0.5, "medium": 1.0, "strong": 1.5}.get(correlation, 1.0)
                total_confidence += confidence * weight
                weight_sum += weight
            
            return total_confidence / weight_sum if weight_sum > 0 else 0.5
            
        except Exception as e:
            logger.error(f"Failed to calculate validation confidence: {str(e)}")
            return 0.5
    
    async def _generate_integration_insights(self, cross_validation: Dict, 
                                           ctem_results: Dict, zta_results: Dict) -> List[IntegrationInsight]:
        """Generate insights from CTEM-ZTA integration"""
        try:
            insights = []
            
            # Policy feedback insights
            policy_validation = cross_validation.get("policy_validation", {})
            if policy_validation.get("overall_effectiveness", 0) < 0.7:
                insights.append(IntegrationInsight(
                    insight_id=f"policy-feedback-{datetime.now().strftime('%H%M%S')}",
                    type=IntegrationType.POLICY_FEEDBACK,
                    source_system="CTEM",
                    target_system="ZTA",
                    finding="CTEM validation shows ZTA policies have gaps against real attack paths",
                    recommendation="Update ZTA policies based on validated attack vectors",
                    priority="high",
                    confidence=0.85,
                    timestamp=datetime.now()
                ))
            
            # Control validation insights
            coverage_analysis = cross_validation.get("coverage_analysis", {})
            if coverage_analysis.get("coverage_percentage", 0) < 0.8:
                insights.append(IntegrationInsight(
                    insight_id=f"coverage-{datetime.now().strftime('%H%M%S')}",
                    type=IntegrationType.CONTROL_VALIDATION,
                    source_system="ZTA",
                    target_system="CTEM",
                    finding="ZTA identified violations not fully covered by CTEM assessment",
                    recommendation="Expand CTEM scope to include all ZTA violation types",
                    priority="medium",
                    confidence=0.75,
                    timestamp=datetime.now()
                ))
            
            # Risk correlation insights
            overlapping_issues = cross_validation.get("overlapping_issues", [])
            high_confidence_issues = [i for i in overlapping_issues if i.get("confidence", 0) > 0.8]
            if high_confidence_issues:
                insights.append(IntegrationInsight(
                    insight_id=f"risk-correlation-{datetime.now().strftime('%H%M%S')}",
                    type=IntegrationType.RISK_CORRELATION,
                    source_system="Integration",
                    target_system="Both",
                    finding=f"Strong correlation found in {len(high_confidence_issues)} security issues",
                    recommendation="Prioritize remediation of correlated high-confidence issues",
                    priority="high",
                    confidence=0.9,
                    timestamp=datetime.now()
                ))
            
            # Store insights
            self.integration_insights.extend(insights)
            
            logger.info(f"Generated {len(insights)} integration insights")
            return insights
            
        except Exception as e:
            logger.error(f"Failed to generate integration insights: {str(e)}")
            return []
    
    async def _apply_feedback_loop(self, insights: List[IntegrationInsight], environment: Dict) -> Dict:
        """Apply feedback loop between CTEM and ZTA systems"""
        try:
            logger.info("🔄 Applying CTEM-ZTA feedback loop")
            
            feedback_results = {
                "policy_updates": 0,
                "scope_adjustments": 0,
                "threshold_modifications": 0,
                "control_enhancements": 0,
                "recommendations_generated": []
            }
            
            for insight in insights:
                if insight.type == IntegrationType.POLICY_FEEDBACK:
                    # CTEM findings inform ZTA policy updates
                    policy_update = await self._update_zta_policies_from_ctem(insight)
                    if policy_update["applied"]:
                        feedback_results["policy_updates"] += 1
                        feedback_results["recommendations_generated"].append(policy_update["recommendation"])
                
                elif insight.type == IntegrationType.CONTROL_VALIDATION:
                    # ZTA violations inform CTEM scope expansion
                    scope_update = await self._expand_ctem_scope_from_zta(insight)
                    if scope_update["applied"]:
                        feedback_results["scope_adjustments"] += 1
                        feedback_results["recommendations_generated"].append(scope_update["recommendation"])
                
                elif insight.type == IntegrationType.RISK_CORRELATION:
                    # Correlated findings enhance both systems
                    enhancement = await self._enhance_controls_from_correlation(insight)
                    if enhancement["applied"]:
                        feedback_results["control_enhancements"] += 1
                        feedback_results["recommendations_generated"].append(enhancement["recommendation"])
            
            # Update integration metrics
            config_metrics = self.integration_config.get("integration_metrics", {})
            config_metrics["policy_updates"] += feedback_results["policy_updates"]
            config_metrics["control_validations"] += feedback_results["scope_adjustments"]
            config_metrics["risk_correlations"] += feedback_results["control_enhancements"]
            
            # Store feedback history
            self.feedback_history.append({
                "timestamp": datetime.now(),
                "insights_processed": len(insights),
                "actions_taken": feedback_results
            })
            
            logger.info(f"Feedback loop applied: {sum([feedback_results[k] for k in ['policy_updates', 'scope_adjustments', 'control_enhancements']])} actions taken")
            return feedback_results
            
        except Exception as e:
            logger.error(f"Failed to apply feedback loop: {str(e)}")
            return {}
    
    async def _update_zta_policies_from_ctem(self, insight: IntegrationInsight) -> Dict:
        """Update ZTA policies based on CTEM findings"""
        try:
            # Simulate policy update (in real implementation, would modify actual policies)
            update_result = {
                "applied": True,
                "policy_type": "access_control",
                "modification": "Tightened access controls based on validated attack paths",
                "recommendation": f"Policy updated: {insight.recommendation}",
                "confidence": insight.confidence
            }
            
            # In a real system, this would update actual ZTA policy engine
            # For demo, we simulate the policy improvement
            if hasattr(self.zta, 'policy_engine'):
                # Increase risk threshold slightly to be more restrictive
                current_threshold = self.zta.policy_engine.get("risk_threshold", 0.7)
                new_threshold = min(0.9, current_threshold + 0.05)
                self.zta.policy_engine["risk_threshold"] = new_threshold
                
                update_result["modification"] = f"Risk threshold updated from {current_threshold} to {new_threshold}"
            
            return update_result
            
        except Exception as e:
            logger.error(f"Failed to update ZTA policies: {str(e)}")
            return {"applied": False, "error": str(e)}
    
    async def _expand_ctem_scope_from_zta(self, insight: IntegrationInsight) -> Dict:
        """Expand CTEM scope based on ZTA violations"""
        try:
            # Simulate scope expansion
            scope_update = {
                "applied": True,
                "scope_type": "assessment_coverage",
                "expansion": "Extended CTEM to cover additional ZTA violation types",
                "recommendation": f"Scope expanded: {insight.recommendation}",
                "confidence": insight.confidence
            }
            
            # In a real system, this would modify CTEM scoping rules
            # For demo, we simulate the scope enhancement
            if hasattr(self.ctem, 'scoped_environment'):
                # Add additional asset types to scope
                current_scope = self.ctem.scoped_environment.get("scope_boundaries", {})
                resource_types = current_scope.get("resource_types", [])
                
                # Add identity-related resources based on ZTA findings
                if "iam" not in resource_types:
                    resource_types.append("iam")
                    scope_update["expansion"] = "Added IAM resources to CTEM scope"
                
                if "identity" not in resource_types:
                    resource_types.append("identity")
            
            return scope_update
            
        except Exception as e:
            logger.error(f"Failed to expand CTEM scope: {str(e)}")
            return {"applied": False, "error": str(e)}
    
    async def _enhance_controls_from_correlation(self, insight: IntegrationInsight) -> Dict:
        """Enhance security controls based on correlated findings"""
        try:
            enhancement = {
                "applied": True,
                "enhancement_type": "detection_capability",
                "improvement": "Enhanced detection based on correlated CTEM-ZTA findings",
                "recommendation": f"Controls enhanced: {insight.recommendation}",
                "confidence": insight.confidence
            }
            
            # Simulate detection capability enhancement
            # In a real system, this might update SIEM rules, deploy new sensors, etc.
            if hasattr(self.zta, 'network_analyzer'):
                # Enable behavioral analytics based on correlation
                self.zta.network_analyzer["behavioral_analytics"] = True
                enhancement["improvement"] = "Enabled behavioral analytics based on correlation"
            
            return enhancement
            
        except Exception as e:
            logger.error(f"Failed to enhance controls: {str(e)}")
            return {"applied": False, "error": str(e)}
    
    async def _calculate_integrated_risk(self, ctem_results: Dict, zta_results: Dict, 
                                       cross_validation: Dict) -> Dict:
        """Calculate integrated risk assessment from both CTEM and ZTA"""
        try:
            # Get individual risk scores
            ctem_summary = ctem_results.get("ctem_summary", {})
            zta_maturity = zta_results.get("overall_zta_maturity", 0)
            
            # Calculate base risk scores
            ctem_risk = ctem_summary.get("overall_risk_score", 0.5)
            zta_risk = 1.0 - (zta_maturity / 100)  # Higher maturity = lower risk
            
            # Apply correlation weighting
            validation_confidence = cross_validation.get("validation_confidence", 0.5)
            
            # Weighted risk calculation
            # Higher confidence in correlation means we trust the combined assessment more
            integrated_risk_score = (
                (ctem_risk * 0.6) + (zta_risk * 0.4)
            ) * (1 + validation_confidence * 0.2)  # Boost risk if highly correlated findings
            
            # Normalize to 0-1 scale
            integrated_risk_score = min(1.0, max(0.0, integrated_risk_score))
            
            # Risk level categorization
            if integrated_risk_score >= 0.8:
                risk_level = "Critical"
            elif integrated_risk_score >= 0.6:
                risk_level = "High"
            elif integrated_risk_score >= 0.4:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            # Business impact assessment
            business_impact = self._assess_integrated_business_impact(
                ctem_results, zta_results, integrated_risk_score
            )
            
            integrated_risk = {
                "overall_risk_score": round(integrated_risk_score, 3),
                "risk_level": risk_level,
                "ctem_risk_component": round(ctem_risk, 3),
                "zta_risk_component": round(zta_risk, 3),
                "correlation_factor": round(validation_confidence, 3),
                "business_impact": business_impact,
                "risk_factors": self._identify_top_risk_factors(ctem_results, zta_results),
                "mitigation_priority": self._calculate_mitigation_priority(integrated_risk_score)
            }
            
            return integrated_risk
            
        except Exception as e:
            logger.error(f"Failed to calculate integrated risk: {str(e)}")
            return {"overall_risk_score": 0.5, "risk_level": "Unknown"}
    
    def _assess_integrated_business_impact(self, ctem_results: Dict, zta_results: Dict, 
                                         risk_score: float) -> Dict:
        """Assess business impact from integrated risk perspective"""
        try:
            # Get individual impact assessments
            ctem_summary = ctem_results.get("ctem_summary", {})
            critical_exposures = ctem_summary.get("critical_exposures", 0)
            high_exposures = ctem_summary.get("high_exposures", 0)
            
            zta_violations = zta_results.get("violations_found", 0)
            
            # Calculate impact metrics
            data_breach_likelihood = min(0.9, risk_score + (critical_exposures * 0.1))
            operational_impact = min(0.8, (high_exposures + zta_violations) * 0.05)
            compliance_risk = min(0.7, risk_score * 0.8)
            
            # Determine impact level
            max_impact = max(data_breach_likelihood, operational_impact, compliance_risk)
            
            if max_impact >= 0.7:
                impact_level = "Critical"
                estimated_cost = risk_score * 1000000  # Scale with risk
            elif max_impact >= 0.5:
                impact_level = "High"
                estimated_cost = risk_score * 500000
            elif max_impact >= 0.3:
                impact_level = "Medium"
                estimated_cost = risk_score * 100000
            else:
                impact_level = "Low"
                estimated_cost = risk_score * 10000
            
            return {
                "impact_level": impact_level,
                "data_breach_likelihood": round(data_breach_likelihood, 3),
                "operational_impact": round(operational_impact, 3),
                "compliance_risk": round(compliance_risk, 3),
                "estimated_cost_usd": round(estimated_cost, 0),
                "affected_assets": critical_exposures + high_exposures,
                "regulatory_implications": impact_level in ["Critical", "High"]
            }
            
        except Exception as e:
            logger.error(f"Failed to assess integrated business impact: {str(e)}")
            return {"impact_level": "Unknown", "estimated_cost_usd": 0}
    
    def _identify_top_risk_factors(self, ctem_results: Dict, zta_results: Dict) -> List[Dict]:
        """Identify top risk factors from integrated analysis"""
        try:
            risk_factors = []
            
            # CTEM-derived risk factors
            ctem_summary = ctem_results.get("ctem_summary", {})
            if ctem_summary.get("critical_exposures", 0) > 0:
                risk_factors.append({
                    "factor": "Critical Vulnerabilities",
                    "source": "CTEM",
                    "count": ctem_summary.get("critical_exposures", 0),
                    "impact": "high",
                    "description": "Critical security exposures validated through CTEM"
                })
            
            # ZTA-derived risk factors
            if zta_results.get("violations_found", 0) > 0:
                risk_factors.append({
                    "factor": "ZTA Policy Violations",
                    "source": "ZTA",
                    "count": zta_results.get("violations_found", 0),
                    "impact": "medium",
                    "description": "Zero Trust Architecture violations detected"
                })
            
            # Identity and access risks
            identity_score = zta_results.get("identity_controls", {}).get("score", 100)
            if identity_score < 70:
                risk_factors.append({
                    "factor": "Identity Controls Weakness",
                    "source": "ZTA",
                    "count": 1,
                    "impact": "high",
                    "description": f"Identity controls score: {identity_score}/100"
                })
            
            return sorted(risk_factors, key=lambda x: {"high": 3, "medium": 2, "low": 1}[x["impact"]], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to identify top risk factors: {str(e)}")
            return []
    
    def _calculate_mitigation_priority(self, risk_score: float) -> List[str]:
        """Calculate mitigation priorities based on integrated risk"""
        try:
            priorities = []
            
            if risk_score >= 0.8:
                priorities = [
                    "Immediate: Address critical vulnerabilities within 24 hours",
                    "Urgent: Implement emergency access controls",
                    "High: Review and update security policies",
                    "Medium: Enhance monitoring and detection"
                ]
            elif risk_score >= 0.6:
                priorities = [
                    "High: Patch critical vulnerabilities within 72 hours",
                    "High: Strengthen access controls and segmentation",
                    "Medium: Update security policies based on findings",
                    "Low: Improve continuous monitoring capabilities"
                ]
            elif risk_score >= 0.4:
                priorities = [
                    "Medium: Address high-priority vulnerabilities",
                    "Medium: Review access control effectiveness",
                    "Low: Optimize security monitoring",
                    "Low: Conduct regular security assessments"
                ]
            else:
                priorities = [
                    "Low: Maintain current security posture",
                    "Low: Continue regular vulnerability management",
                    "Low: Monitor for emerging threats",
                    "Low: Periodic security reviews"
                ]
            
            return priorities
            
        except Exception as e:
            logger.error(f"Failed to calculate mitigation priority: {str(e)}")
            return ["Review security posture and implement appropriate controls"]
    
    def _identify_integrated_attack_paths(self) -> List[Dict]:
        """Identify attack paths considering both CTEM and ZTA findings"""
        try:
            integrated_paths = []
            
            for attack_path in self.ctem.attack_paths:
                # Assess how ZTA would handle this attack path
                zta_effectiveness = self.validation_results.get(attack_path.id, ValidationResult.UNTESTED)
                
                integrated_path = {
                    "path_id": attack_path.id,
                    "description": f"{attack_path.start_asset} → {attack_path.target_asset}",
                    "steps": len(attack_path.steps),
                    "success_probability": attack_path.success_probability,
                    "zta_effectiveness": zta_effectiveness.value,
                    "business_impact": attack_path.impact,
                    "detection_difficulty": attack_path.detection_difficulty,
                    "integrated_risk": self._calculate_path_integrated_risk(attack_path, zta_effectiveness)
                }
                
                integrated_paths.append(integrated_path)
            
            # Sort by integrated risk (highest first)
            return sorted(integrated_paths, key=lambda x: x["integrated_risk"], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to identify integrated attack paths: {str(e)}")
            return []
    
    def _calculate_path_integrated_risk(self, attack_path, zta_effectiveness: ValidationResult) -> float:
        """Calculate integrated risk for a specific attack path"""
        try:
            base_risk = attack_path.success_probability
            
            # Adjust based on ZTA effectiveness
            zta_modifier = {
                ValidationResult.EFFECTIVE: 0.2,
                ValidationResult.PARTIALLY_EFFECTIVE: 0.6,
                ValidationResult.INEFFECTIVE: 1.0,
                ValidationResult.UNTESTED: 0.8
            }.get(zta_effectiveness, 0.8)
            
            # Consider detection difficulty
            detection_modifier = 1 + (attack_path.detection_difficulty * 0.3)
            
            integrated_risk = base_risk * zta_modifier * detection_modifier
            return min(1.0, integrated_risk)
            
        except Exception as e:
            logger.error(f"Failed to calculate path integrated risk: {str(e)}")
            return 0.5
    
    async def _update_security_posture(self, integrated_risk: Dict, insights: List[IntegrationInsight], 
                                     feedback_results: Dict) -> SecurityPosture:
        """Update overall security posture based on integrated analysis"""
        try:
            # Calculate posture score (higher is better)
            risk_score = integrated_risk.get("overall_risk_score", 0.5)
            posture_score = max(0.0, 1.0 - risk_score)
            
            # Determine risk level
            risk_level = integrated_risk.get("risk_level", "Unknown")
            
            # Calculate component scores
            zta_maturity = 0.0
            if hasattr(self.zta, 'zta_violations'):
                # Simulate ZTA maturity calculation
                zta_maturity = max(0.0, 1.0 - (len(self.zta.zta_violations) * 0.1))
            
            ctem_coverage = 0.0
            if hasattr(self.ctem, 'exposures'):
                total_exposures = len(self.ctem.exposures)
                validated_exposures = len([e for e in self.ctem.exposures if e.validated])
                ctem_coverage = validated_exposures / max(total_exposures, 1)
            
            # Calculate integration effectiveness
            successful_feedback = sum([
                feedback_results.get("policy_updates", 0),
                feedback_results.get("scope_adjustments", 0),
                feedback_results.get("control_enhancements", 0)
            ])
            total_insights = len(insights)
            integration_effectiveness = successful_feedback / max(total_insights, 1)
            
            # Identify critical gaps
            critical_gaps = []
            if risk_score > 0.7:
                critical_gaps.append("High overall security risk detected")
            if zta_maturity < 0.6:
                critical_gaps.append("Zero Trust Architecture maturity is insufficient")
            if ctem_coverage < 0.8:
                critical_gaps.append("CTEM validation coverage needs improvement")
            
            # Identify improvement areas
            improvement_areas = []
            for insight in insights:
                if insight.priority == "high":
                    improvement_areas.append(insight.recommendation)
            
            return SecurityPosture(
                posture_score=round(posture_score, 3),
                risk_level=risk_level,
                zta_maturity=round(zta_maturity, 3),
                ctem_coverage=round(ctem_coverage, 3),
                integration_effectiveness=round(integration_effectiveness, 3),
                critical_gaps=critical_gaps,
                improvement_areas=improvement_areas[:5],  # Top 5 areas
                last_assessment=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Failed to update security posture: {str(e)}")
            return SecurityPosture(
                posture_score=0.5,
                risk_level="Unknown",
                zta_maturity=0.0,
                ctem_coverage=0.0,
                integration_effectiveness=0.0,
                critical_gaps=["Unable to assess security posture"],
                improvement_areas=[],
                last_assessment=datetime.now()
            )

    async def continuous_validation_cycle(self, environment: Dict, ai_engine=None, 
                                        cycles: int = 1, cycle_interval: int = 60) -> Dict:
        """Run continuous validation cycle for ongoing CTEM-ZTA integration with AI enhancement"""
        try:
            logger.info(f"🔄 Running Continuous Validation Cycle ({cycles} cycles)")
            
            all_cycles_results = []
            total_risk_reduction = 0
            total_ai_insights = 0
            cycle_improvements = []
            
            for cycle_num in range(cycles):
                logger.info(f"Starting validation cycle {cycle_num + 1}/{cycles}")
                
                # Track changes since last assessment
                changes_detected = await self._detect_environment_changes(environment)
                
                # Run incremental assessments if changes detected
                if changes_detected["significant_changes"]:
                    logger.info("Significant changes detected - running incremental assessment")
                    incremental_results = await self._run_incremental_assessment(environment)
                else:
                    logger.info("No significant changes - running status check")
                    incremental_results = await self._run_status_check()
                
                # AI Enhancement: Run AI analysis if engine provided
                ai_insights_this_cycle = 0
                if ai_engine:
                    logger.info("🤖 Running AI-enhanced analysis for this cycle")
                    
                    # Simulate AI insights generation
                    ai_insights_this_cycle = 2  # Simulate 2 insights per cycle
                    total_ai_insights += ai_insights_this_cycle
                    
                    # Generate cycle improvement based on AI analysis
                    improvements = [
                        "Identified new behavioral anomaly patterns",
                        "Improved threat prediction accuracy",
                        "Discovered additional attack path correlations",
                        "Enhanced vulnerability clustering results",
                        "Optimized risk prioritization algorithms"
                    ]
                    if cycle_num < len(improvements):
                        cycle_improvements.append(improvements[cycle_num])
                
                # Update trends and metrics
                trend_analysis = self._analyze_security_trends()
                
                # Calculate risk reduction for this cycle
                cycle_risk_reduction = 10 + (cycle_num * 2.5)  # Simulate improving effectiveness
                total_risk_reduction += cycle_risk_reduction
                
                cycle_result = {
                    "cycle_number": cycle_num + 1,
                    "cycle_timestamp": datetime.now().isoformat(),
                    "changes_detected": changes_detected,
                    "incremental_results": incremental_results,
                    "trend_analysis": trend_analysis,
                    "new_exposures": incremental_results.get("new_exposures", 0),
                    "remediated": incremental_results.get("remediated_count", 0),
                    "risk_trend": trend_analysis.get("risk_direction", "stable"),
                    "ai_insights_generated": ai_insights_this_cycle,
                    "risk_reduction_percentage": cycle_risk_reduction
                }
                
                all_cycles_results.append(cycle_result)
                
                # Sleep between cycles if multiple cycles and interval specified
                if cycles > 1 and cycle_num < cycles - 1 and cycle_interval > 0:
                    logger.info(f"Waiting {cycle_interval} seconds before next cycle...")
                    await asyncio.sleep(cycle_interval)
            
            # Aggregate results across all cycles
            avg_risk_reduction = total_risk_reduction / cycles if cycles > 0 else 0
            avg_ai_insights = total_ai_insights / cycles if cycles > 0 else 0
            
            validation_results = {
                "cycles_completed": cycles,
                "cycle_results": all_cycles_results,
                "avg_risk_reduction": round(avg_risk_reduction, 2),
                "total_ai_insights": total_ai_insights,
                "ai_insights_per_cycle": round(avg_ai_insights, 1),
                "cycle_improvements": cycle_improvements,
                "overall_trend": "improving" if avg_risk_reduction > 10 else "stable",
                "ai_enhanced": ai_engine is not None,
                "final_timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"Continuous validation cycle completed: {cycles} cycles, "
                       f"{avg_risk_reduction:.1f}% avg risk reduction")
            return validation_results
            
        except Exception as e:
            logger.error(f"Continuous validation cycle failed: {str(e)}")
            return {"error": str(e), "cycles_completed": 0}
    
    async def _detect_environment_changes(self, environment: Dict) -> Dict:
        """Detect significant changes in the environment"""
        try:
            # Simulate change detection
            # In real implementation, would compare against previous state
            return {
                "significant_changes": False,
                "new_resources": 0,
                "modified_resources": 0,
                "removed_resources": 0,
                "policy_changes": 0
            }
        except Exception as e:
            logger.error(f"Failed to detect environment changes: {str(e)}")
            return {"significant_changes": False}
    
    async def _run_incremental_assessment(self, environment: Dict) -> Dict:
        """Run incremental security assessment"""
        try:
            # Simulate incremental assessment
            return {
                "new_exposures": 0,
                "remediated_count": 1,
                "policy_effectiveness": 0.85
            }
        except Exception as e:
            logger.error(f"Failed to run incremental assessment: {str(e)}")
            return {}
    
    async def _run_status_check(self) -> Dict:
        """Run status check of current security posture"""
        try:
            return {
                "new_exposures": 0,
                "remediated_count": 0,
                "status": "stable"
            }
        except Exception as e:
            logger.error(f"Failed to run status check: {str(e)}")
            return {}
    
    def _analyze_security_trends(self) -> Dict:
        """Analyze security trends over time"""
        try:
            # Simulate trend analysis based on feedback history
            if len(self.feedback_history) >= 2:
                recent_feedback = self.feedback_history[-1]
                previous_feedback = self.feedback_history[-2]
                
                recent_actions = sum(recent_feedback.get("actions_taken", {}).values())
                previous_actions = sum(previous_feedback.get("actions_taken", {}).values())
                
                if recent_actions > previous_actions:
                    risk_direction = "improving"
                elif recent_actions < previous_actions:
                    risk_direction = "degrading"
                else:
                    risk_direction = "stable"
            else:
                risk_direction = "stable"
            
            return {
                "risk_direction": risk_direction,
                "feedback_cycles": len(self.feedback_history),
                "total_insights": len(self.integration_insights),
                "trend_confidence": 0.7
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze security trends: {str(e)}")
            return {"risk_direction": "unknown"}
