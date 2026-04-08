from fastapi import Header, HTTPException
from jose import JWTError, jwt

from app.config import JWT_ALGORITHM, JWT_SECRET


def require_jwt(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid JWT token") from exc
    return str(payload.get("sub", "admin"))
