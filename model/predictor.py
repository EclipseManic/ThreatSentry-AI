# model/predictor.py
import pickle
import os
from db import get_session, Device
from config import MODEL_PATH
from logger import get_logger

logger = get_logger("predictor")

def load_model():
    if not os.path.exists(MODEL_PATH):
        logger.warning("Model not found at %s", MODEL_PATH)
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

def predict_and_store(model=None):
    session = get_session()
    if model is None:
        model = load_model()
    if model is None:
        session.close()
        logger.warning("No model available to predict.")
        return
    devices = session.query(Device).all()
    for d in devices:
        num_ports = d.num_open_ports or 0
        cve_count = d.cve_count or 0
        max_cvss = d.max_cvss or 0.0
        exposure = d.exposure_days or 0
        X = [[num_ports, cve_count, float(max_cvss), exposure]]
        try:
            pred = model.predict(X)[0]
            d.risk_label = int(pred)
        except Exception:
            logger.exception("Prediction failed for device %s", d.ip)
    session.commit()
    session.close()
    logger.info("Predicted risk label for devices and updated DB.")
