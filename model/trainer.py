# model/trainer.py
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np
from db import get_session, Device
from logger import get_logger
from config import MODEL_PATH

logger = get_logger("trainer")

def load_training_data():
    session = get_session()
    devices = session.query(Device).all()
    X = []
    y = []
    for d in devices:
        num_ports = d.num_open_ports or 0
        cve_count = d.cve_count or 0
        max_cvss = d.max_cvss or 0.0
        exposure = d.exposure_days or 0
        X.append([num_ports, cve_count, float(max_cvss), exposure])
        # synthetic labels (bootstrap). Replace with real labeled data in production.
        label = 0
        if max_cvss >= 9 or num_ports > 20:
            label = 2
        elif max_cvss >= 7 or num_ports > 8:
            label = 1
        y.append(label)
    session.close()
    if not X:
        return None, None
    return np.array(X), np.array(y)

def train_and_save_model():
    X, y = load_training_data()
    if X is None:
        logger.warning("No training data available. Skipping model training.")
        return None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    logger.info(f"Trained RandomForest model saved to {MODEL_PATH} with test score {score:.3f}")
    from model.predictor import predict_and_store
    predict_and_store(clf)
    return clf
