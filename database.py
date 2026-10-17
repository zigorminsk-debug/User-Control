import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    Boolean, Index, desc
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config import get_config

Base = declarative_base()


class AccessDeniedEvent(Base):
    __tablename__ = "access_denied_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String(255), nullable=False)
    domain = Column(String(255), default="")
    source_ip = Column(String(50), default="")
    file_path = Column(Text, nullable=False)
    access_mask = Column(String(50), default="")
    access_reason = Column(Text, default="")
    process_name = Column(Text, default="")
    event_id = Column(Integer, default=0)
    raw_message = Column(Text, default="")
    severity = Column(String(20), default="warning")  # info, warning, critical

    __table_args__ = (
        Index("ix_ad_timestamp", "timestamp"),
        Index("ix_ad_username", "username"),
        Index("ix_ad_severity", "severity"),
    )


class ClipboardEvent(Base):
    __tablename__ = "clipboard_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String(255), nullable=False)
    session_id = Column(Integer, default=0)
    session_name = Column(String(100), default="")
    content_type = Column(String(50), default="text")
    content_preview = Column(Text, default="")
    content_length = Column(Integer, default=0)
    source_app = Column(String(255), default="")
    is_suspicious = Column(Boolean, default=False)
    reason = Column(Text, default="")

    __table_args__ = (
        Index("ix_cb_timestamp", "timestamp"),
        Index("ix_cb_username", "username"),
        Index("ix_cb_suspicious", "is_suspicious"),
    )


class FileOperationEvent(Base):
    __tablename__ = "file_operation_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String(255), nullable=False)
    operation = Column(String(50), nullable=False)  # copy, move, delete, rename
    source_path = Column(Text, nullable=False)
    dest_path = Column(Text, default="")
    file_size = Column(Integer, default=0)
    file_extension = Column(String(20), default="")
    is_suspicious = Column(Boolean, default=False)
    reason = Column(Text, default="")

    __table_args__ = (
        Index("ix_fo_timestamp", "timestamp"),
        Index("ix_fo_username", "username"),
        Index("ix_fo_operation", "operation"),
    )


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = Column(String(255), nullable=False)
    domain = Column(String(255), default="")
    source_ip = Column(String(50), default="")
    event_type = Column(String(50), nullable=False)  # success, failure, logout
    logon_type = Column(String(50), default="")
    failure_reason = Column(Text, default="")
    event_id = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_login_timestamp", "timestamp"),
        Index("ix_login_username", "username"),
        Index("ix_login_type", "event_type"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="warning")
    username = Column(String(255), default="")
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    is_read = Column(Boolean, default=False)
    is_acknowledged = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_alert_timestamp", "timestamp"),
        Index("ix_alert_read", "is_read"),
        Index("ix_alert_severity", "severity"),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False)
    session_id = Column(Integer, default=0)
    session_name = Column(String(100), default="")
    client_name = Column(String(255), default="")
    client_ip = Column(String(50), default="")
    login_time = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    __table_args__ = (
        Index("ix_session_username", "username"),
        Index("ix_session_active", "is_active"),
    )


class Database:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        cfg = get_config()
        db_path = cfg.get("db_path", "monitor.db")
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self):
        return self.Session()

    # ---- Access Denied ----
    def add_access_denied(self, **kwargs):
        s = self.get_session()
        try:
            ev = AccessDeniedEvent(**kwargs)
            s.add(ev)
            s.commit()
            return ev.id
        finally:
            s.close()

    def get_access_denied(self, limit=200, offset=0, username=None, start=None, end=None):
        s = self.get_session()
        try:
            q = s.query(AccessDeniedEvent).order_by(desc(AccessDeniedEvent.timestamp))
            if username:
                q = q.filter(AccessDeniedEvent.username == username)
            if start:
                q = q.filter(AccessDeniedEvent.timestamp >= start)
            if end:
                q = q.filter(AccessDeniedEvent.timestamp <= end)
            return q.offset(offset).limit(limit).all()
        finally:
            s.close()

    # ---- Clipboard ----
    def add_clipboard_event(self, **kwargs):
        s = self.get_session()
        try:
            ev = ClipboardEvent(**kwargs)
            s.add(ev)
            s.commit()
            return ev.id
        finally:
            s.close()

    def get_clipboard_events(self, limit=200, offset=0, username=None, suspicious_only=False, start=None, end=None):
        s = self.get_session()
        try:
            q = s.query(ClipboardEvent).order_by(desc(ClipboardEvent.timestamp))
            if username:
                q = q.filter(ClipboardEvent.username == username)
            if suspicious_only:
                q = q.filter(ClipboardEvent.is_suspicious == True)
            if start:
                q = q.filter(ClipboardEvent.timestamp >= start)
            if end:
                q = q.filter(ClipboardEvent.timestamp <= end)
            return q.offset(offset).limit(limit).all()
        finally:
            s.close()

    # ---- File Operations ----
    def add_file_operation(self, **kwargs):
        s = self.get_session()
        try:
            ev = FileOperationEvent(**kwargs)
            s.add(ev)
            s.commit()
            return ev.id
        finally:
            s.close()

    def get_file_operations(self, limit=200, offset=0, username=None, operation=None, start=None, end=None):
        s = self.get_session()
        try:
            q = s.query(FileOperationEvent).order_by(desc(FileOperationEvent.timestamp))
            if username:
                q = q.filter(FileOperationEvent.username == username)
            if operation:
                q = q.filter(FileOperationEvent.operation == operation)
            if start:
                q = q.filter(FileOperationEvent.timestamp >= start)
            if end:
                q = q.filter(FileOperationEvent.timestamp <= end)
            return q.offset(offset).limit(limit).all()
        finally:
            s.close()

    # ---- Login Events ----
    def add_login_event(self, **kwargs):
        s = self.get_session()
        try:
            ev = LoginEvent(**kwargs)
            s.add(ev)
            s.commit()
            return ev.id
        finally:
            s.close()

    def get_login_events(self, limit=200, offset=0, username=None, event_type=None, start=None, end=None):
        s = self.get_session()
        try:
            q = s.query(LoginEvent).order_by(desc(LoginEvent.timestamp))
            if username:
                q = q.filter(LoginEvent.username == username)
            if event_type:
                q = q.filter(LoginEvent.event_type == event_type)
            if start:
                q = q.filter(LoginEvent.timestamp >= start)
            if end:
                q = q.filter(LoginEvent.timestamp <= end)
            return q.offset(offset).limit(limit).all()
        finally:
            s.close()

    # ---- Alerts ----
    def add_alert(self, **kwargs):
        s = self.get_session()
        try:
            ev = Alert(**kwargs)
            s.add(ev)
            s.commit()
            return ev.id
        finally:
            s.close()

    def get_alerts(self, limit=100, unread_only=False):
        s = self.get_session()
        try:
            q = s.query(Alert).order_by(desc(Alert.timestamp))
            if unread_only:
                q = q.filter(Alert.is_read == False)
            return q.offset(0).limit(limit).all()
        finally:
            s.close()

    def acknowledge_alert(self, alert_id):
        s = self.get_session()
        try:
            a = s.query(Alert).filter(Alert.id == alert_id).first()
            if a:
                a.is_acknowledged = True
                a.is_read = True
                s.commit()
        finally:
            s.close()

    # ---- User Sessions ----
    def upsert_user_session(self, username, session_id, session_name="", client_name="", client_ip=""):
        s = self.get_session()
        try:
            now = datetime.datetime.utcnow()
            existing = (
                s.query(UserSession)
                .filter(UserSession.username == username, UserSession.session_id == session_id, UserSession.is_active == True)
                .first()
            )
            if existing:
                existing.last_activity = now
                existing.client_name = client_name or existing.client_name
                existing.client_ip = client_ip or existing.client_ip
            else:
                us = UserSession(
                    username=username,
                    session_id=session_id,
                    session_name=session_name,
                    client_name=client_name,
                    client_ip=client_ip,
                    login_time=now,
                    last_activity=now,
                    is_active=True,
                )
                s.add(us)
            s.commit()
        finally:
            s.close()

    def deactivate_session(self, username, session_id):
        s = self.get_session()
        try:
            existing = (
                s.query(UserSession)
                .filter(UserSession.username == username, UserSession.session_id == session_id, UserSession.is_active == True)
                .first()
            )
            if existing:
                existing.is_active = False
                s.commit()
        finally:
            s.close()

    def get_active_sessions(self):
        s = self.get_session()
        try:
            return s.query(UserSession).filter(UserSession.is_active == True).all()
        finally:
            s.close()

    # ---- Statistics ----
    def get_stats(self, hours=24):
        s = self.get_session()
        try:
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
            ad_count = s.query(AccessDeniedEvent).filter(AccessDeniedEvent.timestamp >= cutoff).count()
            cb_count = s.query(ClipboardEvent).filter(ClipboardEvent.timestamp >= cutoff).count()
            cb_suspicious = s.query(ClipboardEvent).filter(ClipboardEvent.timestamp >= cutoff, ClipboardEvent.is_suspicious == True).count()
            fo_count = s.query(FileOperationEvent).filter(FileOperationEvent.timestamp >= cutoff).count()
            login_success = s.query(LoginEvent).filter(LoginEvent.timestamp >= cutoff, LoginEvent.event_type == "success").count()
            login_failure = s.query(LoginEvent).filter(LoginEvent.timestamp >= cutoff, LoginEvent.event_type == "failure").count()
            alert_count = s.query(Alert).filter(Alert.timestamp >= cutoff, Alert.is_read == False).count()
            return {
                "access_denied": ad_count,
                "clipboard_total": cb_count,
                "clipboard_suspicious": cb_suspicious,
                "file_operations": fo_count,
                "login_success": login_success,
                "login_failure": login_failure,
                "unread_alerts": alert_count,
                "period_hours": hours,
            }
        finally:
            s.close()

    def get_user_stats(self, hours=24):
        s = self.get_session()
        try:
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
            from sqlalchemy import func

            ad_users = (
                s.query(AccessDeniedEvent.username, func.count(AccessDeniedEvent.id))
                .filter(AccessDeniedEvent.timestamp >= cutoff)
                .group_by(AccessDeniedEvent.username)
                .order_by(desc(func.count(AccessDeniedEvent.id)))
                .limit(20)
                .all()
            )
            cb_users = (
                s.query(ClipboardEvent.username, func.count(ClipboardEvent.id))
                .filter(ClipboardEvent.timestamp >= cutoff)
                .group_by(ClipboardEvent.username)
                .order_by(desc(func.count(ClipboardEvent.id)))
                .limit(20)
                .all()
            )
            return {
                "access_denied_by_user": [{"username": u, "count": c} for u, c in ad_users],
                "clipboard_by_user": [{"username": u, "count": c} for u, c in cb_users],
            }
        finally:
            s.close()

    def get_timeline(self, hours=24):
        s = self.get_session()
        try:
            from sqlalchemy import func, extract
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
            ad_timeline = (
                s.query(
                    func.strftime("%Y-%m-%d %H:00:00", AccessDeniedEvent.timestamp).label("hour"),
                    func.count(AccessDeniedEvent.id).label("count"),
                )
                .filter(AccessDeniedEvent.timestamp >= cutoff)
                .group_by("hour")
                .order_by("hour")
                .all()
            )
            cb_timeline = (
                s.query(
                    func.strftime("%Y-%m-%d %H:00:00", ClipboardEvent.timestamp).label("hour"),
                    func.count(ClipboardEvent.id).label("count"),
                )
                .filter(ClipboardEvent.timestamp >= cutoff)
                .group_by("hour")
                .order_by("hour")
                .all()
            )
            return {
                "access_denied_timeline": [{"hour": h, "count": c} for h, c in ad_timeline],
                "clipboard_timeline": [{"hour": h, "count": c} for h, c in cb_timeline],
            }
        finally:
            s.close()


def get_db():
    return Database.get_instance()