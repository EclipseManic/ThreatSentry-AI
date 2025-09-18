"""
Training orchestrator for the advanced threat detection model
"""
import numpy as np
from datetime import datetime, timezone
import json
import os
from typing import Tuple, List, Dict, Any

from db import get_session, Device
from config import MODEL_PATH
from logger import get_logger
from .feature_engineering import FeatureEngineer
from .advanced_model import EnsembleModel

logger = get_logger("model_training")

class ModelTrainingOrchestrator:
    def __init__(self):
        self.feature_engineer = FeatureEngineer()
        self.model = EnsembleModel()
        self.training_metadata = {
            'last_training': None,
            'samples_trained': 0,
            'current_performance': {}
        }
    
    def prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from the database with advanced feature engineering
        """
        session = get_session()
        devices = session.query(Device).all()
        
        if not devices:
            logger.warning("No devices found for training")
            session.close()
            return None, None
            
        # Extract features for all devices
        X = self.feature_engineer.batch_extract_features(devices)
        
        # Generate sophisticated labels based on multiple factors
        y = self._generate_advanced_labels(devices)
        
        session.close()
        return X, y
    
    def _generate_advanced_labels(self, devices: List[Device]) -> np.ndarray:
        """
        Generate sophisticated labels using multiple risk factors
        """
        labels = []
        for device in devices:
            risk_score = 0
            
            # Vulnerability-based risk (40% weight)
            if device.max_cvss is not None:
                risk_score += (device.max_cvss / 10.0) * 40
            
            # Exposure-based risk (20% weight)
            if device.num_open_ports > 0:
                port_risk = min(device.num_open_ports / 20.0, 1.0) * 20
                risk_score += port_risk
            
            # Behavioral risk (20% weight)
            behavioral_risk = 0
            if device.auth_failures_24h > 0:
                behavioral_risk += min(device.auth_failures_24h / 100.0, 1.0) * 10
            if device.traffic_anomaly_score > 0:
                behavioral_risk += device.traffic_anomaly_score * 10
            risk_score += behavioral_risk
            
            # Context-based risk (20% weight)
            context_risk = 0
            if device.is_critical_service:
                context_risk += 10
            if device.data_sensitivity_level:
                context_risk += (device.data_sensitivity_level / 5.0) * 10
            risk_score += context_risk
            
            # Convert score to label
            if risk_score >= 70:
                labels.append(2)  # High risk
            elif risk_score >= 40:
                labels.append(1)  # Medium risk
            else:
                labels.append(0)  # Low risk
        
        return np.array(labels)
    
    def train_model(self) -> bool:
        """
        Train the model with advanced features and validation
        """
        logger.info("Starting advanced model training")
        
        # Prepare training data
        X, y = self.prepare_training_data()
        if X is None or len(X) == 0:
            logger.error("No training data available")
            return False
            
        # Fit feature scaler
        self.feature_engineer.fit_scaler(X)
        X_scaled = self.feature_engineer.transform_features(X)
        
        # Train the model
        self.model.fit(X_scaled, y)
        
        # Update training metadata
        self.training_metadata['last_training'] = datetime.now(timezone.utc).isoformat()
        self.training_metadata['samples_trained'] = len(X)
        self.training_metadata['current_performance'] = self.model.validation_metrics
        
        # Save the trained model and metadata
        self._save_model_and_metadata()
        
        logger.info("Model training completed successfully")
        logger.info(f"Validation accuracy: {self.model.validation_metrics['accuracy']:.3f}")
        
        return True
    
    def predict_and_update(self) -> None:
        """
        Make predictions for all devices and update the database
        """
        session = get_session()
        devices = session.query(Device).all()
        
        if not devices:
            logger.warning("No devices found for prediction")
            session.close()
            return
        
        # Extract features
        X = self.feature_engineer.batch_extract_features(devices)
        X_scaled = self.feature_engineer.transform_features(X)
        
        # Get predictions and explanations
        predictions = self.model.predict(X_scaled)
        explanations = self.model.get_prediction_explanation(X_scaled)
        
        # Update devices with predictions and explanations
        for device, pred, explanation in zip(devices, predictions, explanations):
            device.risk_label = int(pred)
            device.risk_score = float(explanation['confidence'] * 100)
            device.confidence_score = float(explanation['confidence'])
            device.last_analysis_date = datetime.now(timezone.utc)
            
            # Store feature importance information
            contrib_features = {
                feat['feature_idx']: feat['importance']
                for feat in explanation['contributing_features']
            }
            device.alert_history = json.dumps(contrib_features)
        
        session.commit()
        session.close()
        logger.info(f"Updated predictions for {len(devices)} devices")
    
    def _save_model_and_metadata(self) -> None:
        """
        Save model and associated metadata
        """
        # Save the model
        self.model.save_model(MODEL_PATH)
        
        # Save metadata alongside the model
        metadata_path = os.path.splitext(MODEL_PATH)[0] + '_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(self.training_metadata, f, indent=2)
        
        logger.info(f"Model and metadata saved to {MODEL_PATH}")
    
    @classmethod
    def load_latest_model(cls) -> 'ModelTrainingOrchestrator':
        """
        Load the latest trained model and metadata
        """
        orchestrator = cls()
        
        if os.path.exists(MODEL_PATH):
            orchestrator.model = EnsembleModel.load_model(MODEL_PATH)
            
            # Load metadata if available
            metadata_path = os.path.splitext(MODEL_PATH)[0] + '_metadata.json'
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    orchestrator.training_metadata = json.load(f)
                    
            logger.info("Loaded existing model and metadata")
        else:
            logger.warning("No existing model found, will need to train new model")
        
        return orchestrator