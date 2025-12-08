"""
Feedback system for continuous model improvement
"""
from datetime import datetime, timezone
import json
import numpy as np
from typing import Dict, List, Optional
from db import get_session, Device
from logger import get_logger
from .feature_engineering import FeatureEngineer
from .advanced_model import EnsembleModel

logger = get_logger("feedback_system")

class FeedbackSystem:
    def __init__(self, model: EnsembleModel, feature_engineer: FeatureEngineer):
        self.model = model
        self.feature_engineer = feature_engineer
        self.feedback_history = []
        self.adjustment_threshold = 10  # Number of feedback items before model adjustment
    
    def record_feedback(self, 
                       device_id: int, 
                       actual_risk: int, 
                       feedback_source: str,
                       feedback_notes: Optional[str] = None) -> Dict:
        """
        Record feedback from security team about a device's risk classification
        """
        session = get_session()
        try:
            device = session.query(Device).filter_by(id=device_id).first()
            
            if not device:
                return {"success": False, "error": "Device not found"}
            
            # Get current prediction
            features = self.feature_engineer.extract_features(device)
            features_scaled = self.feature_engineer.transform_features(features.reshape(1, -1))
            current_pred = self.model.predict(features_scaled)[0]
            
            # Record feedback
            feedback_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "device_id": device_id,
                "predicted_risk": int(current_pred),
                "actual_risk": actual_risk,
                "feedback_source": feedback_source,
                "feedback_notes": feedback_notes,
                "features": features.tolist()
            }
            
            # Update device metrics
            device.prediction_accuracy = 1.0 if current_pred == actual_risk else 0.0
            device.last_true_positive = datetime.now(timezone.utc) if actual_risk > 0 else None
            if current_pred != actual_risk:
                device.false_positive_count += 1
            
            # Store feedback
            self.feedback_history.append(feedback_entry)
            
            # If we have enough feedback, trigger model adjustment
            if len(self.feedback_history) >= self.adjustment_threshold:
                self._adjust_model()
            
            session.commit()
            
            return {
                "success": True,
                "feedback_id": len(self.feedback_history) - 1,
                "requires_adjustment": len(self.feedback_history) >= self.adjustment_threshold
            }
        except Exception as e:
            logger.error("Failed to record feedback: %s", str(e))
            session.rollback()
            return {"success": False, "error": str(e)}
        finally:
            session.close()
    
    def _adjust_model(self) -> None:
        """
        Adjust model based on accumulated feedback
        """
        try:
            logger.info("Starting model adjustment based on feedback")
            
            # Prepare feedback data
            X_feedback = []
            y_feedback = []
            
            for entry in self.feedback_history:
                X_feedback.append(entry["features"])
                y_feedback.append(entry["actual_risk"])
            
            X_feedback = np.array(X_feedback)
            y_feedback = np.array(y_feedback)
            
            # Validate data
            if len(X_feedback) == 0 or len(np.unique(y_feedback)) < 1:
                logger.warning("Insufficient feedback data for model adjustment")
                return
            
            # Scale features
            X_feedback_scaled = self.feature_engineer.transform_features(X_feedback)
            
            # Update model weights based on performance
            self._update_model_weights()
            
            # Retrain model with feedback data
            self.model.fit(X_feedback_scaled, y_feedback)
            
            # Clear feedback history after adjustment
            self.feedback_history = []
            
            logger.info("Model adjusted successfully with feedback data")
        except Exception as e:
            logger.error("Failed to adjust model: %s", str(e))
    
    def _update_model_weights(self) -> None:
        """
        Update ensemble model weights based on individual model performance
        """
        correct_predictions = {
            'rf': 0,
            'gb': 0,
            'nn': 0
        }
        
        # Calculate correct predictions for each model
        for entry in self.feedback_history:
            features = np.array(entry["features"]).reshape(1, -1)
            features_scaled = self.feature_engineer.transform_features(features)
            actual = entry["actual_risk"]
            
            # Check each model's prediction
            rf_pred = self.model.rf_model.predict(features_scaled)[0]
            gb_pred = self.model.gb_model.predict(features_scaled)[0]
            nn_pred = self.model.nn_model.predict(features_scaled)[0]
            
            correct_predictions['rf'] += 1 if rf_pred == actual else 0
            correct_predictions['gb'] += 1 if gb_pred == actual else 0
            correct_predictions['nn'] += 1 if nn_pred == actual else 0
        
        # Calculate new weights based on accuracy
        total_correct = sum(correct_predictions.values())
        if total_correct > 0:
            new_weights = {
                model: (correct / total_correct) 
                for model, correct in correct_predictions.items()
            }
            
            # Update weights with smoothing
            for model in self.model.model_weights:
                current_weight = self.model.model_weights[model]
                new_weight = new_weights[model]
                # Smooth transition (70% old weight, 30% new weight)
                self.model.model_weights[model] = 0.7 * current_weight + 0.3 * new_weight
    
    def analyze_feedback_trends(self) -> Dict:
        """
        Analyze trends in feedback data
        """
        if not self.feedback_history:
            return {"error": "No feedback data available"}
        
        analysis = {
            "total_feedback": len(self.feedback_history),
            "accuracy": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "risk_distribution": {0: 0, 1: 0, 2: 0},
            "common_misclassifications": []
        }
        
        for entry in self.feedback_history:
            pred = entry["predicted_risk"]
            actual = entry["actual_risk"]
            
            # Update statistics
            analysis["accuracy"] += 1 if pred == actual else 0
            analysis["risk_distribution"][actual] += 1
            
            if pred > actual:
                analysis["false_positives"] += 1
            elif pred < actual:
                analysis["false_negatives"] += 1
        
        # Calculate percentages
        total = len(self.feedback_history)
        analysis["accuracy"] = (analysis["accuracy"] / total) * 100
        analysis["false_positive_rate"] = (analysis["false_positives"] / total) * 100
        analysis["false_negative_rate"] = (analysis["false_negatives"] / total) * 100
        
        return analysis
    
    def save_feedback_history(self, filepath: str) -> None:
        """
        Save feedback history to file
        """
        with open(filepath, 'w') as f:
            json.dump(self.feedback_history, f, indent=2)
    
    def load_feedback_history(self, filepath: str) -> None:
        """
        Load feedback history from file
        """
        with open(filepath, 'r') as f:
            self.feedback_history = json.load(f)