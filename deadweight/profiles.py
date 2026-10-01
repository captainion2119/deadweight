"""Create AWS CLI/SDK profiles: access keys, IAM Identity Center (SSO) or assume-role.

Writes the same files the AWS CLI uses (~/.aws/config and ~/.aws/credentials, or the paths in
AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE). Existing content, comments included, is left untouched:
a profile's section is appended, or replaced in place when overwriting, and a .bak copy of each file
is kept before it changes. Secrets are never logged."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import boto3
from botocore import UNSIGNED
from botocore.config import Config

NAME_RE = re.compile(r"^[A-Za-z0-9_.+@-]{1,64}$")


def config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config").expanduser()


def credentials_path() -> Path:
    return Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials").expanduser()


def list_profiles() -> list[str]:
    try:
        return sorted(boto3.Session().available_profiles)
    except Exception:
        return []


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Profile names may use letters, digits and _ . + @ - (max 64)")
    return name


# ── file editing ──────────────────────────────────────────────────────────────

def _upsert_section(path: Path, header: str, items: dict[str, str]) -> None:
    """Replace the body of [header] (or append the section) without disturbing anything else."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    body = "".join(f"{k} = {v}\n" for k, v in items.items() if v not in (None, ""))
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if l.strip() == f"[{header}]"), None)
    if start is None:
        sep = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        new = f"{text}{sep}[{header}]\n{body}"
    else:
        end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
        tail = lines[end:]
        new = "".join(lines[:start + 1]) + body + ("\n" if tail else "") + "".join(tail)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(new, encoding="utf-8")
    os.replace(tmp, path)
    if path == credentials_path() and os.name != "nt":
        os.chmod(path, 0o600)


def _config_header(name: str) -> str:
    return "default" if name == "default" else f"profile {name}"


def profile_exists(name: str) -> bool:
    return name in list_profiles()


# ── profile kinds ─────────────────────────────────────────────────────────────

def identity_for_keys(access_key_id: str, secret: str, session_token: str | None = None) -> dict:
    sts = boto3.client("sts", aws_access_key_id=access_key_id.strip(), aws_secret_access_key=secret.strip(),
                       aws_session_token=(session_token or "").strip() or None, region_name="us-east-1")
    return sts.get_caller_identity()


def add_access_key_profile(name: str, access_key_id: str, secret: str, session_token: str | None = None,
                           region: str = "us-east-1") -> None:
    name = check_name(name)
    if not access_key_id.strip() or not secret.strip():
        raise ValueError("Access key ID and secret access key are required")
    _upsert_section(credentials_path(), name, {"aws_access_key_id": access_key_id.strip(),
                                               "aws_secret_access_key": secret.strip(),
                                               "aws_session_token": (session_token or "").strip()})
    _upsert_section(config_path(), _config_header(name), {"region": region.strip(), "output": "json"})


def add_role_profile(name: str, role_arn: str, source_profile: str, region: str = "us-east-1",
                     external_id: str | None = None) -> None:
    name = check_name(name)
    if not role_arn.strip().startswith("arn:"):
        raise ValueError("Role ARN must look like arn:aws:iam::123456789012:role/ReadOnly")
    _upsert_section(config_path(), _config_header(name), {"role_arn": role_arn.strip(), "source_profile": source_profile,
                                                          "external_id": (external_id or "").strip(),
                                                          "region": region.strip(), "output": "json"})


def add_sso_profile(name: str, session_name: str, start_url: str, sso_region: str, account_id: str, role_name: str,
                    region: str = "us-east-1") -> None:
    name, session_name = check_name(name), check_name(session_name)
    _upsert_section(config_path(), f"sso-session {session_name}", {
        "sso_start_url": start_url.strip(), "sso_region": sso_region.strip(), "sso_registration_scopes": "sso:account:access"})
    _upsert_section(config_path(), _config_header(name), {
        "sso_session": session_name, "sso_account_id": account_id.strip(), "sso_role_name": role_name.strip(),
        "region": region.strip(), "output": "json"})


def validate(name: str) -> dict:
    return boto3.Session(profile_name=name).client("sts", region_name="us-east-1").get_caller_identity()


# ── IAM Identity Center sign-in (what `aws sso login` does) ───────────────────

@dataclass
class DeviceCode:
    url: str
    user_code: str
    expires_in: int


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sso_login(session_name: str, start_url: str, sso_region: str, on_code: Callable[[DeviceCode], None],
              cancelled: Callable[[], bool] = lambda: False, open_browser: bool = True) -> str:
    """Device-authorisation sign-in. Writes the token cache botocore reads for `sso_session` profiles and
    returns the access token."""
    oidc = boto3.client("sso-oidc", region_name=sso_region, config=Config(signature_version=UNSIGNED))
    reg = oidc.register_client(clientName="deadweight", clientType="public", scopes=["sso:account:access"])
    auth = oidc.start_device_authorization(clientId=reg["clientId"], clientSecret=reg["clientSecret"], startUrl=start_url)
    code = DeviceCode(auth.get("verificationUriComplete") or auth["verificationUri"], auth["userCode"], int(auth.get("expiresIn", 600)))
    on_code(code)
    if open_browser:
        try:
            webbrowser.open(code.url)
        except Exception:
            pass
    interval, deadline = int(auth.get("interval") or 5), time.monotonic() + code.expires_in
    while time.monotonic() < deadline:
        if cancelled():
            raise RuntimeError("Sign-in cancelled")
        time.sleep(interval)
        try:
            tok = oidc.create_token(clientId=reg["clientId"], clientSecret=reg["clientSecret"],
                                    grantType="urn:ietf:params:oauth:grant-type:device_code", deviceCode=auth["deviceCode"])
        except oidc.exceptions.AuthorizationPendingException:
            continue
        except oidc.exceptions.SlowDownException:
            interval += 5
            continue
        now = datetime.now(timezone.utc)
        cache = {"startUrl": start_url, "region": sso_region, "accessToken": tok["accessToken"],
                 "expiresAt": _iso(now + timedelta(seconds=int(tok.get("expiresIn", 3600)))),
                 "clientId": reg["clientId"], "clientSecret": reg["clientSecret"],
                 "registrationExpiresAt": _iso(datetime.fromtimestamp(int(reg.get("clientSecretExpiresAt", 0)), timezone.utc))}
        if tok.get("refreshToken"):
            cache["refreshToken"] = tok["refreshToken"]
        cache_dir = Path.home() / ".aws" / "sso" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / (hashlib.sha1(session_name.encode("utf-8")).hexdigest() + ".json")
        path.write_text(json.dumps(cache), encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)
        return tok["accessToken"]
    raise RuntimeError("Sign-in code expired before it was approved")


def sso_accounts(access_token: str, sso_region: str) -> list[tuple[str, str, list[str]]]:
    """(account id, account name, role names) the signed-in user can use."""
    sso = boto3.client("sso", region_name=sso_region, config=Config(signature_version=UNSIGNED))
    out = []
    for page in sso.get_paginator("list_accounts").paginate(accessToken=access_token):
        for a in page.get("accountList", []):
            roles = [r["roleName"] for p in sso.get_paginator("list_account_roles").paginate(accessToken=access_token, accountId=a["accountId"])
                     for r in p.get("roleList", [])]
            out.append((a["accountId"], a.get("accountName", ""), sorted(roles)))
    return sorted(out, key=lambda x: x[1].lower())
