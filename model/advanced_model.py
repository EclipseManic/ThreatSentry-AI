"""
Advanced ML model architecture combining multiple algorithms
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any

class EnsembleModel:
    def __init__(self):
        # Initialize base models
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            class_weight='balanced'
        )
        
        self.gb_model = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,
            min_samples_split=5
        )
        
        self.nn_model = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            max_iter=1000,
            early_stopping=True
        )
        
        self.model_weights = {
            'rf': 0.4,
            'gb': 0.4,
            'nn': 0.2
        }
        
        self.feature_importances_ = None
        self.training_history = []
        self.validation_metrics = {}
        
    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train all models in the ensemble
        """
        # Split data for training and validation
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        # Basic safety checks
        unique_train_classes = np.unique(y_train)
        if len(unique_train_classes) < 2:
            raise ValueError("Training requires at least 2 classes in the training set")

        # If training set is small, disable NN early stopping to avoid MLP internal
        # validation-split errors (small splits can lead to zero samples per class)
        try:
            if X_train.shape[0] < max(30, len(unique_train_classes) * 5):
                # turn off early stopping for small datasets
                self.nn_model.set_params(early_stopping=False)
        except Exception:
            # If the estimator doesn't support set_params for some reason, ignore
            pass

        # Train each model
        self.rf_model.fit(X_train, y_train)
        self.gb_model.fit(X_train, y_train)
        self.nn_model.fit(X_train, y_train)
        
        # Calculate and store feature importances
        self.feature_importances_ = self._compute_feature_importance()
        
        # Calculate validation metrics
        self._calculate_validation_metrics(X_val, y_val)
        
        # Record training event
        self.training_history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'samples': len(X),
            'features': X.shape[1],
            'validation_accuracy': self.validation_metrics['accuracy']
        })
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Generate weighted ensemble predictions
        """
        # Get predictions from each model
        rf_pred = self.rf_model.predict_proba(X)
        gb_pred = self.gb_model.predict_proba(X)
        nn_pred = self.nn_model.predict_proba(X)
        
        # Weighted average of probabilities
        weighted_probs = (
            rf_pred * self.model_weights['rf'] +
            gb_pred * self.model_weights['gb'] +
            nn_pred * self.model_weights['nn']
        )
        
        return np.argmax(weighted_probs, axis=1)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Generate weighted probability predictions
        """
        rf_pred = self.rf_model.predict_proba(X)
        gb_pred = self.gb_model.predict_proba(X)
        nn_pred = self.nn_model.predict_proba(X)
        
        return (
            rf_pred * self.model_weights['rf'] +
            gb_pred * self.model_weights['gb'] +
            nn_pred * self.model_weights['nn']
        )
    
    def _compute_feature_importance(self) -> np.ndarray:
        """
        Compute combined feature importance scores
        """
        rf_importance = self.rf_model.feature_importances_
        gb_importance = self.gb_model.feature_importances_
        
        # Neural network doesn't provide feature importance, so we use only RF and GB
        combined_importance = (
            rf_importance * (self.model_weights['rf'] / (self.model_weights['rf'] + self.model_weights['gb'])) +
            gb_importance * (self.model_weights['gb'] / (self.model_weights['rf'] + self.model_weights['gb']))
        )
        
        return combined_importance
    
    def _calculate_validation_metrics(self, X_val: np.ndarray, y_val: np.ndarray) -> None:
        """
        Calculate and store validation metrics
        """
        y_pred = self.predict(X_val)
        
        self.validation_metrics = {
            'accuracy': np.mean(y_pred == y_val),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
            'classification_report': classification_report(y_val, y_pred, output_dict=True)
        }
    
    def get_prediction_explanation(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """
        Generate detailed explanation for predictions
        """
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        
        explanations = []
        for idx, (pred, probs) in enumerate(zip(predictions, probabilities)):
            contrib_features = []
            feature_importance = self.feature_importances_
            
            # Get top contributing features
            for feat_idx in np.argsort(X[idx] * feature_importance)[-5:]:
                contrib_features.append({
                    'feature_idx': int(feat_idx),
                    'importance': float(feature_importance[feat_idx]),
                    'value': float(X[idx, feat_idx])
                })
            
            explanations.append({
                'prediction': int(pred),
                'confidence': float(np.max(probs)),
                'class_probabilities': probs.tolist(),
                'contributing_features': contrib_features
            })
        
        return explanations
    
    def save_model(self, filepath: str) -> None:
        """
        Save the ensemble model to disk
        """
        model_data = {
            'rf_model': self.rf_model,
            'gb_model': self.gb_model,
            'nn_model': self.nn_model,
            'model_weights': self.model_weights,
            'feature_importances': self.feature_importances_,
            'training_history': self.training_history,
            'validation_metrics': self.validation_metrics
        }
        joblib.dump(model_data, filepath)
    
    @classmethod
    def load_model(cls, filepath: str) -> 'EnsembleModel':
        """
        Load the ensemble model from disk
        """
        model = cls()
        model_data = joblib.load(filepath)
        
        model.rf_model = model_data['rf_model']
        model.gb_model = model_data['gb_model']
        model.nn_model = model_data['nn_model']
        model.model_weights = model_data['model_weights']
        model.feature_importances_ = model_data['feature_importances']
        model.training_history = model_data['training_history']
        model.validation_metrics = model_data['validation_metrics']
        
        return model