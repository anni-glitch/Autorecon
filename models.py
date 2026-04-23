from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
import datetime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    api_key = Column(String, unique=True, index=True, nullable=True)
    is_active = Column(Boolean, default=True)

    jobs = relationship("ScanJob", back_populates="owner")
    schedules = relationship("ScheduledScan", back_populates="owner")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    status = Column(String, default="pending") # pending, running, completed, error
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    module = Column(String)
    category = Column(String)
    severity = Column(String)
    title = Column(String)
    description = Column(String)

    job = relationship("ScanJob", back_populates="findings")

class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    stealth = Column(Boolean, default=False)
    interval_hours = Column(Integer, default=24)
    modules = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="schedules")
