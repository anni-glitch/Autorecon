import os
import re
import hashlib
import httpx
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Cookie, Header
from sqlalchemy.orm import Session
from dotenv import load_dotenv

import database
import models

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-development-only")
ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "1440"))
REFRESH_EXPIRATION_DAYS = int(os.getenv("REFRESH_EXPIRATION_DAYS", "7"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def validate_password_complexity(password: str):
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character.")

async def is_password_compromised(password: str) -> bool:
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    limits = httpx.Limits(max_connections=5)
    async with httpx.AsyncClient(limits=limits) as client:
        try:
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if resp.status_code == 200:
                hashes = (line.split(':')[0] for line in resp.text.splitlines())
                return suffix in hashes
        except Exception:
            pass
    return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=JWT_EXPIRATION_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=REFRESH_EXPIRATION_DAYS))
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    access_token: Optional[str] = Cookie(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(database.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not Authenticated",
    )
    
    # Process API Key if present
    if x_api_key:
        user = db.query(models.User).filter(models.User.api_key == x_api_key).first()
        if user:
            return user
        raise credentials_exception

    # Process JWT fallback
    if not access_token:
        raise credentials_exception
        
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user
