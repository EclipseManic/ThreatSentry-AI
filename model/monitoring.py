"""
Model monitoring and validation system
"""
from datetime import datetime, timezone
import numpy as np
from typing import Dict, List, Optional
from sklearn.metrics import confusion_matrix, classification_report
import json
from data import get_session, Device
from core import get_logger
from .feature_engineering import FeatureEngineer
from .advanced_model import EnsembleModel

logger = get_logger("model_monitoring")

class ModelMonitor:
    def __init__(self, model: EnsembleModel, feature_engineer: FeatureEngineer):
        self.model = model
        self.feature_engineer = feature_engineer
        self.performance_history = []
        self.drift_metrics = {
            'feature_drift': {},
            'prediction_drift': {},
            'concept_drift': {}
        }
        
    def calculate_performance_metrics(self) -> Dict:
        """
        Calculate comprehensive model performance metrics
        """
        session = get_session()
        try:
            devices = session.query(Device).all()
            
            if not devices:
                return {"error": "No devices found"}
            
            # Extract features and actual labels
            X = self.feature_engineer.batch_extract_features(devices)
            X_scaled = self.feature_engineer.transform_features(X)
            y_true = np.array([d.risk_label for d in devices])
            y_pred = self.model.predict(X_scaled)
            
            # Calculate metrics
            metrics = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'accuracy': float(np.mean(y_true == y_pred)),
                'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
                'classification_report': classification_report(y_true, y_pred, output_dict=True),
                'prediction_distribution': {
                    'low': int(np.sum(y_pred == 0)),
                    'medium': int(np.sum(y_pred == 1)),
                    'high': int(np.sum(y_pred == 2))
                }
            }
            
            # Add confidence metrics
            probas = self.model.predict_proba(X_scaled)
            metrics['avg_confidence'] = float(np.mean(np.max(probas, axis=1)))
            metrics['low_confidence_predictions'] = int(np.sum(np.max(probas, axis=1) < 0.7))
            
            self.performance_history.append(metrics)
            
            return metrics
        except Exception as e:
            logger.error("Failed to calculate performance metrics: %s", str(e))
            return {"error": str(e)}
        finally:
            session.close()
    
    def detect_feature_drift(self, reference_data: np.ndarray) -> Dict:
        """
        Detect drift in feature distributions
        """
        session = get_session()
        try:
            devices = session.query(Device).all()
            
            if not devices:
                return {"error": "No devices found"}
            
            current_data = self.feature_engineer.batch_extract_features(devices)
            
            drift_scores = {}
            feature_names = getattr(self.feature_engineer, 'feature_names', [])
            
            if not feature_names:
                logger.warning("Feature names not available for drift detection")
                return {"drift_scores": {}, "warning": "Feature names not available"}
            
            for i, feature_name in enumerate(feature_names):
                if i >= len(reference_data[0]):
                    logger.warning("Feature index %d out of range", i)
                    continue
                    
                # Calculate distribution differences
                ref_dist = reference_data[:, i]
                curr_dist = current_data[:, i]
                
                # Calculate KL divergence for continuous features
                ref_hist = np.histogram(ref_dist, bins=20, density=True)[0]
                curr_hist = np.histogram(curr_dist, bins=20, density=True)[0]
                
                # Add smoothing to avoid division by zero
                ref_hist = ref_hist + 1e-10
                curr_hist = curr_hist + 1e-10
                
                # Calculate KL divergence
                kl_div = np.sum(ref_hist * np.log(ref_hist / curr_hist))
                
                drift_scores[feature_name] = {
                    'drift_score': float(kl_div),
                'significant_drift': kl_div > 0.5,  # Threshold can be adjusted
                'mean_difference': float(np.mean(curr_dist) - np.mean(ref_dist)),
                'std_difference': float(np.std(curr_dist) - np.std(ref_dist))
            }
        
        self.drift_metrics['feature_drift'] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'scores': drift_scores
        }
        
        session.close()
        return self.drift_metrics['feature_drift']
    
    def detect_prediction_drift(self, historical_predictions: List[int]) -> Dict:
        """
        Detect drift in model predictions over time
        """
        session = get_session()
        devices = session.query(Device).all()
        
        if not devices:
            session.close()
            return {"error": "No devices found"}
        
        # Get current predictions
        X = self.feature_engineer.batch_extract_features(devices)
        X_scaled = self.feature_engineer.transform_features(X)
        current_predictions = self.model.predict(X_scaled)
        
        # Calculate distribution shifts
        hist_dist = np.bincount(historical_predictions, minlength=3) / len(historical_predictions)
        curr_dist = np.bincount(current_predictions, minlength=3) / len(current_predictions)
        
        # Calculate Jensen-Shannon divergence
        m = 0.5 * (hist_dist + curr_dist)
        js_div = 0.5 * (
            np.sum(hist_dist * np.log(hist_dist / m)) +
            np.sum(curr_dist * np.log(curr_dist / m))
        )
        
        drift_info = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'jensen_shannon_div': float(js_div),
            'significant_drift': js_div > 0.1,  # Threshold can be adjusted
            'historical_distribution': hist_dist.tolist(),
            'current_distribution': curr_dist.tolist()
        }
        
        self.drift_metrics['prediction_drift'] = drift_info
        session.close()
        
        return drift_info
    
    def monitor_model_health(self) -> Dict:
        """
        Comprehensive model health check
        """
        health_metrics = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'performance_metrics': self.calculate_performance_metrics(),
            'drift_detected': False,
            'warnings': [],
            'recommendations': []
        }
        
        # Check performance degradation
        if len(self.performance_history) > 1:
            current_acc = health_metrics['performance_metrics']['accuracy']
            prev_acc = self.performance_history[-2]['accuracy']
            
            if current_acc < prev_acc * 0.9:  # 10% degradation
                health_metrics['warnings'].append(
                    "Significant performance degradation detected"
                )
                health_metrics['recommendations'].append(
                    "Consider retraining the model with recent data"
                )
        
        # Check prediction confidence
        if health_metrics['performance_metrics']['low_confidence_predictions'] > 100:
            health_metrics['warnings'].append(
                "High number of low-confidence predictions"
            )
            health_metrics['recommendations'].append(
                "Review feature engineering and model architecture"
            )
        
        # Check prediction distribution
        pred_dist = health_metrics['performance_metrics']['prediction_distribution']
        total_preds = sum(pred_dist.values())
        
        for risk_level, count in pred_dist.items():
            if count / total_preds > 0.8:  # More than 80% predictions in one class
                health_metrics['warnings'].append(
                    f"Suspicious prediction distribution: {risk_level} risk predictions dominant"
                )
                health_metrics['recommendations'].append(
                    "Review class balancing and threshold settings"
                )
        
        return health_metrics
    
    def save_monitoring_data(self, filepath: str) -> None:
        """
        Save monitoring data to file
        """
        monitoring_data = {
            'performance_history': self.performance_history,
            'drift_metrics': self.drift_metrics,
            'last_update': datetime.now(timezone.utc).isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(monitoring_data, f, indent=2)
    
    def load_monitoring_data(self, filepath: str) -> None:
        """
        Load monitoring data from file
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.performance_history = data['performance_history']
            self.drift_metrics = data['drift_metrics']