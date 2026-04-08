import ipaddress
import subprocess

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.api.deps import require_jwt
from app.config import SOAR_ENABLED
from app.services.audit import log_audit_event

router = APIRouter()


class SoarActionIn(BaseModel):
    action: str
    target: str
    dry_run: bool = True
    confirm: bool = False

    @field_validator("target")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(
                "Target must be a valid IPv4 or IPv6 address"
            )
        return v.strip()


@router.post("/action")
def run_soar_action(body: SoarActionIn, actor: str = Depends(require_jwt)):
    if not SOAR_ENABLED:
        raise HTTPException(status_code=403, detail="SOAR is disabled")
    if body.action != "block_ip":
        raise HTTPException(status_code=400, detail="Unsupported action")

    if not body.dry_run and not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Live actions require confirm=true for safety",
        )

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name=IDS_Block_{body.target}",
        "dir=out",
        "action=block",
        f"remoteip={body.target}",
    ]
    if body.dry_run:
        log_audit_event(actor, "soar.block_ip.dry_run", "soar.action", {"target": body.target})
        return {"ok": True, "dry_run": True, "command": " ".join(cmd)}

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    log_audit_event(
        actor,
        "soar.block_ip",
        "soar.action",
        {"target": body.target, "exit_code": result.returncode},
    )
    return {
        "ok": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
    }
