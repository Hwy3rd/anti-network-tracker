"""
Model Trainer - Train ML models để detect reconnaissance attacks
"""
import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from utils import setup_logger
import config

logger = setup_logger(__name__, config.LOG_FILE)

class ModelTrainer:
    """Train and manage detection models"""
    
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None
        self.feature_names = [
            'packet_rate', 'inter_packet_delay', 'time_span',
            'port_diversity', 'unique_dst_ports', 'unique_dst_ips',
            'unique_src_ips', 'syn_ratio', 'ack_ratio',
            'fin_rst_ratio', 'null_flags_ratio', 'response_rate',
            'avg_ttl', 'ttl_variance', 'avg_payload_size',
            'payload_variance', 'arp_count', 'arp_request_ratio',
            'sequential_ports'
        ]
    
    def train(self, X_train, y_train):
        """
        Train classification model
        
        Args:
            X_train: Training features (n_samples, n_features)
            y_train: Training labels (n_samples,)
        
        Returns:
            Training accuracy and metrics
        """
        logger.info(f"Training classifier on {len(X_train)} samples")
        
        # Initialize scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train Random Forest Classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=config.RANDOM_STATE,
            n_jobs=-1,
            class_weight='balanced'  # Handle class imbalance
        )
        
        self.classifier.fit(X_scaled, y_train)
        
        # Evaluate on training set
        y_pred = self.classifier.predict(X_scaled)
        accuracy = accuracy_score(y_train, y_pred)
        
        logger.info(f"Classifier trained with accuracy: {accuracy:.4f}")
        logger.debug("\nClassification Report:")
        logger.debug(classification_report(y_train, y_pred))
        
        return {
            'accuracy': accuracy,
            'n_features': X_train.shape[1],
            'n_samples': len(X_train),
        }
    
    def train_anomaly_detector(self, X_train):
        """
        Train Isolation Forest for anomaly detection
        
        Args:
            X_train: Training features (n_samples, n_features)
        
        Returns:
            Training info
        """
        logger.info(f"Training anomaly detector on {len(X_train)} samples")
        
        # Use the same scaler as classifier
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X_train)
        else:
            X_scaled = self.scaler.transform(X_train)
        
        # Train Isolation Forest
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Assume 10% are outliers
            random_state=config.RANDOM_STATE,
            n_jobs=-1
        )
        
        self.anomaly_detector.fit(X_scaled)
        
        logger.info("Anomaly detector trained")
        
        return {
            'n_features': X_train.shape[1],
            'n_samples': len(X_train),
        }
    
    def predict(self, X):
        """
        Predict label for features
        
        Args:
            X: Features (1d array or 2d array)
        
        Returns:
            Predicted label (0=normal, 1=attack) or None if model not trained
        """
        if self.classifier is None or self.scaler is None:
            logger.warning("Classifier not trained yet")
            return None
        
        # Ensure 2D
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        X_scaled = self.scaler.transform(X)
        prediction = self.classifier.predict(X_scaled)[0]
        confidence = self.classifier.predict_proba(X_scaled)[0]
        
        return {
            'label': prediction,
            'label_name': 'attack' if prediction == 1 else 'normal',
            'confidence': max(confidence),
            'probabilities': {
                'normal': confidence[0],
                'attack': confidence[1] if len(confidence) > 1 else 0
            }
        }
    
    def detect_anomaly(self, X):
        """
        Detect if sample is anomalous
        
        Args:
            X: Features (1d array or 2d array)
        
        Returns:
            Anomaly score or None if detector not trained
        """
        if self.anomaly_detector is None or self.scaler is None:
            logger.warning("Anomaly detector not trained yet")
            return None
        
        # Ensure 2D
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (-1 = anomaly, 1 = normal)
        prediction = self.anomaly_detector.predict(X_scaled)[0]
        score = self.anomaly_detector.score_samples(X_scaled)[0]
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': score,  # More negative = more anomalous
            'anomaly_threshold': self.anomaly_detector.offset_
        }
    
    def save_models(self, classifier_path=None, scaler_path=None, anomaly_path=None):
        """Save trained models to disk"""
        classifier_path = classifier_path or config.MODEL_PATH
        scaler_path = scaler_path or config.SCALER_PATH
        anomaly_path = anomaly_path or config.ANOMALY_MODEL_PATH
        
        os.makedirs(os.path.dirname(classifier_path), exist_ok=True)
        
        if self.classifier:
            joblib.dump(self.classifier, classifier_path)
            logger.info(f"Classifier saved to {classifier_path}")
        
        if self.scaler:
            joblib.dump(self.scaler, scaler_path)
            logger.info(f"Scaler saved to {scaler_path}")
        
        if self.anomaly_detector:
            joblib.dump(self.anomaly_detector, anomaly_path)
            logger.info(f"Anomaly detector saved to {anomaly_path}")
    
    def load_models(self, classifier_path=None, scaler_path=None, anomaly_path=None):
        """Load trained models from disk"""
        classifier_path = classifier_path or config.MODEL_PATH
        scaler_path = scaler_path or config.SCALER_PATH
        anomaly_path = anomaly_path or config.ANOMALY_MODEL_PATH
        
        try:
            if os.path.exists(classifier_path):
                self.classifier = joblib.load(classifier_path)
                logger.info(f"Classifier loaded from {classifier_path}")
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Scaler loaded from {scaler_path}")
            
            if os.path.exists(anomaly_path):
                self.anomaly_detector = joblib.load(anomaly_path)
                logger.info(f"Anomaly detector loaded from {anomaly_path}")
        
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    def get_feature_importance(self):
        """Get feature importance from classifier"""
        if self.classifier is None:
            return None
        
        importance = self.classifier.feature_importances_
        feature_importance_dict = dict(zip(self.feature_names, importance))
        
        # Sort by importance
        sorted_importance = sorted(
            feature_importance_dict.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_importance
