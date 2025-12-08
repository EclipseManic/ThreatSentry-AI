"""
Database models and helpers

Defines the SQLAlchemy ORM models used by the application (Device and
Vulnerability) and provides simple helpers to initialize and obtain DB sessions.
This module uses SQLite by default; change `SQLITE_PATH` in `config.py` to
point to a different database file.
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import datetime
from config import SQLITE_PATH
from logger import get_logger

logger = get_logger("db")
Base = declarative_base()

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, nullable=False)
    org = Column(String)
    country = Column(String)
    
    # Basic metrics
    num_open_ports = Column(Integer, default=0)
    banners = Column(Text)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    cve_count = Column(Integer, default=0)
    max_cvss = Column(Float, nullable=True)
    exposure_days = Column(Integer, default=0)
    
    # Enhanced security metrics
    auth_failures_24h = Column(Integer, default=0)  # Authentication failures in last 24h
    traffic_anomaly_score = Column(Float, default=0.0)  # 0-1 score for traffic pattern anomalies
    patch_lag_days = Column(Integer, default=0)  # Days since last security patch
    suspicious_activities_count = Column(Integer, default=0)  # Count of suspicious activities
    data_sensitivity_level = Column(Integer, default=1)  # 1-5 scale of data sensitivity
    
    # Service and infrastructure context
    is_critical_service = Column(Boolean, default=False)  # Is this a critical service
    service_category = Column(String)  # web, database, auth, etc.
    infrastructure_type = Column(String)  # cloud, on-prem, hybrid
    compliance_requirements = Column(String)  # PCI-DSS, HIPAA, etc.
    
    # Historical context
    incident_history_count = Column(Integer, default=0)  # Number of past security incidents
    average_resolution_time = Column(Float)  # Average time to resolve incidents (hours)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_compromise_date = Column(DateTime, nullable=True)
    
    # Network context
    network_segment = Column(String)  # DMZ, internal, etc.
    firewall_rules_count = Column(Integer, default=0)  # Number of firewall rules
    connected_critical_assets = Column(Integer, default=0)  # Number of connected critical assets
    
    # ML and analysis fields
    risk_label = Column(Integer, default=0)  # 0:Low, 1:Med, 2:High
    risk_score = Column(Float, default=0.0)  # Continuous risk score 0-100
    confidence_score = Column(Float, default=0.0)  # Model confidence 0-1
    last_analysis_date = Column(DateTime)
    prediction_accuracy = Column(Float, default=0.0)  # Historical prediction accuracy
    
    # Alert management
    notified = Column(Boolean, default=False)
    alert_history = Column(Text)  # JSON string of past alerts
    false_positive_count = Column(Integer, default=0)
    last_true_positive = Column(DateTime, nullable=True)

    vulnerabilities = relationship("Vulnerability", back_populates="device", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('devices.id'))
    cve_id = Column(String)
    cvss = Column(Float, nullable=True)
    summary = Column(Text)

    device = relationship("Device", back_populates="vulnerabilities")

def get_engine():
    try:
        engine = create_engine(f"sqlite:///{SQLITE_PATH}", echo=False, connect_args={"check_same_thread": False})
        logger.info("Database engine created successfully")
        return engine
    except Exception as e:
        logger.error("Failed to create database engine: %s", str(e))
        raise

def init_db():
    try:
        engine = get_engine()
        Base.metadata.create_all(engine)
        logger.info("DB initialized at %s", SQLITE_PATH)
        return engine
    except Exception as e:
        logger.error("Failed to initialize database: %s", str(e))
        raise

_engine = None
_Session = None

def get_session():
    global _engine, _Session
    try:
        if _engine is None:
            _engine = get_engine()
        if _Session is None:
            _Session = sessionmaker(bind=_engine)
        session = _Session()
        logger.debug("Database session created")
        return session
    except Exception as e:
        logger.error("Failed to create database session: %s", str(e))
        raise
