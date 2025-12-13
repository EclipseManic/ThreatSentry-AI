"""
Advanced feature engineering for threat detection model
"""
import numpy as np
from datetime import datetime, timezone
from sklearn.preprocessing import StandardScaler
from data import Device, get_session
import json

class FeatureEngineer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names = None
    
    def _calculate_temporal_risk(self, device):
        """Calculate risk based on temporal patterns"""
        current_time = datetime.now(timezone.utc)
        exposure_weight = min(device.exposure_days / 365, 1.0) * 10  # Cap at 1 year
        
        # Recent activity risk
        if device.last_compromise_date:
            days_since_compromise = (current_time - device.last_compromise_date).days
            compromise_risk = np.exp(-days_since_compromise / 365) * 20  # Exponential decay
        else:
            compromise_risk = 0
            
        # Patch lag risk
        patch_risk = min(device.patch_lag_days / 30, 1.0) * 15  # Cap at 30 days
        
        return exposure_weight + compromise_risk + patch_risk
    
    def _calculate_network_risk(self, device):
        """Calculate risk based on network context"""
        # Base network risk
        if device.network_segment == 'DMZ':
            base_risk = 20
        elif device.network_segment == 'internal':
            base_risk = 10
        else:
            base_risk = 15
            
        # Connected assets risk
        connected_risk = min(device.connected_critical_assets * 5, 25)
        
        # Firewall complexity risk (more rules = more potential misconfigs)
        firewall_risk = min(device.firewall_rules_count / 100, 1.0) * 10
        
        return base_risk + connected_risk + firewall_risk
    
    def _calculate_service_risk(self, device):
        """Calculate risk based on service context"""
        # Critical service risk
        if device.is_critical_service:
            base_risk = 25
        else:
            base_risk = 10
            
        # Service category risk
        category_risk = {
            'web': 20,
            'database': 25,
            'auth': 30,
            'api': 20,
            'file': 15
        }.get(device.service_category, 10)
        
        # Data sensitivity
        sensitivity_risk = device.data_sensitivity_level * 5
        
        return base_risk + category_risk + sensitivity_risk
    
    def _calculate_behavior_risk(self, device):
        """Calculate risk based on behavior patterns"""
        # Authentication failures risk
        auth_risk = min(device.auth_failures_24h / 100, 1.0) * 25
        
        # Traffic anomaly risk
        traffic_risk = device.traffic_anomaly_score * 20
        
        # Suspicious activity risk
        suspicious_risk = min(device.suspicious_activities_count / 10, 1.0) * 25
        
        return auth_risk + traffic_risk + suspicious_risk
    
    def _calculate_compliance_risk(self, device):
        """Calculate risk based on compliance requirements"""
        if not device.compliance_requirements:
            return 0
            
        requirements = device.compliance_requirements.split(',')
        base_risk = len(requirements) * 5  # More requirements = more risk
        
        # Additional risk for high-regulation requirements
        if 'PCI-DSS' in requirements:
            base_risk += 10
        if 'HIPAA' in requirements:
            base_risk += 15
        if 'SOX' in requirements:
            base_risk += 10
            
        return min(base_risk, 30)  # Cap at 30
    
    def extract_features(self, device):
        """Extract comprehensive feature vector from device"""
        # Basic vulnerability features
        vuln_features = [
            device.num_open_ports,
            device.cve_count,
            device.max_cvss or 0.0,
            device.exposure_days
        ]
        
        # Advanced risk scores
        risk_scores = [
            self._calculate_temporal_risk(device),
            self._calculate_network_risk(device),
            self._calculate_service_risk(device),
            self._calculate_behavior_risk(device),
            self._calculate_compliance_risk(device)
        ]
        
        # Behavioral features
        behavioral_features = [
            device.auth_failures_24h,
            device.traffic_anomaly_score,
            device.suspicious_activities_count,
            device.incident_history_count,
            device.false_positive_count
        ]
        
        # Context features (one-hot encoded)
        network_segment_map = {'DMZ': 1, 'internal': 0, 'unknown': 0.5}
        infrastructure_map = {'cloud': 1, 'on-prem': 0, 'hybrid': 0.5}
        
        context_features = [
            network_segment_map.get(device.network_segment, 0.5),
            infrastructure_map.get(device.infrastructure_type, 0.5),
            device.is_critical_service * 1.0,
            device.data_sensitivity_level / 5.0
        ]
        
        # Combine all features
        features = vuln_features + risk_scores + behavioral_features + context_features
        
        if self.feature_names is None:
            self.feature_names = [
                'num_open_ports', 'cve_count', 'max_cvss', 'exposure_days',
                'temporal_risk', 'network_risk', 'service_risk', 'behavior_risk', 'compliance_risk',
                'auth_failures', 'traffic_anomaly', 'suspicious_activities', 'incident_history', 'false_positives',
                'network_segment', 'infrastructure', 'is_critical', 'data_sensitivity'
            ]
        
        return np.array(features)
    
    def get_feature_importance_report(self, feature_values, risk_score):
        """Generate detailed report of which features contributed to the risk score"""
        report = []
        for name, value in zip(self.feature_names, feature_values):
            contribution = abs(value * 0.1)  # Simplified linear contribution
            report.append({
                'feature': name,
                'value': float(value),
                'contribution': float(contribution)
            })
        return sorted(report, key=lambda x: x['contribution'], reverse=True)
    
    def batch_extract_features(self, devices):
        """Extract features for multiple devices"""
        features = []
        for device in devices:
            features.append(self.extract_features(device))
        return np.array(features)
    
    def fit_scaler(self, features):
        """Fit the scaler to the feature set"""
        self.scaler.fit(features)
    
    def transform_features(self, features):
        """Scale features using fitted scaler"""
        return self.scaler.transform(features)