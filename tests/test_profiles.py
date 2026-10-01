import asyncio
import json
import sys
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import fixture  # noqa: F401,E402  (fake credentials)
import boto3  # noqa: E402
from botocore.stub import Stubber  # noqa: E402
from moto import mock_aws  # noqa: E402

from deadweight import profiles  # noqa: E402

EXISTING_CONFIG = """# my hand-written comment
[default]
region = eu-west-1

[profile prod]
region = us-east-1
# keep me
"""
EXISTING_CREDS = "[default]\naws_access_key_id = AKIAOLD\naws_secret_access_key = oldsecret\n"


@pytest.fixture
def aws_files(tmp_path, monkeypatch):
    cfg, creds = tmp_path / "config", tmp_path / "credentials"
    cfg.write_text(EXISTING_CONFIG, encoding="utf-8")
    creds.write_text(EXISTING_CREDS, encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setattr(profiles.Path, "home", lambda: tmp_path)
    return cfg, creds


def test_access_key_profile_appends_and_preserves(aws_files):
    cfg, creds = aws_files
    profiles.add_access_key_profile("cost-readonly", "AKIANEW", "s3cret", None, "ap-south-1")
    c, k = cfg.read_text(), creds.read_text()
    assert "# my hand-written comment" in c and "# keep me" in c
    assert "[profile cost-readonly]\nregion = ap-south-1\noutput = json\n" in c
    assert "[cost-readonly]\naws_access_key_id = AKIANEW\naws_secret_access_key = s3cret\n" in k
    assert "aws_session_token" not in k.split("[cost-readonly]")[1]       # blank values are not written
    assert (cfg.parent / "config.bak").read_text() == EXISTING_CONFIG
    assert "cost-readonly" in profiles.list_profiles()


def test_overwrite_replaces_in_place(aws_files):
    cfg, _ = aws_files
    profiles.add_role_profile("prod", "arn:aws:iam::111122223333:role/ReadOnly", "default", "us-west-2")
    c = cfg.read_text()
    assert c.count("[profile prod]") == 1
    assert "role_arn = arn:aws:iam::111122223333:role/ReadOnly" in c and "# keep me" not in c.split("[profile prod]")[1]
    assert c.startswith("# my hand-written comment\n[default]\nregion = eu-west-1\n")


def test_bad_inputs(aws_files):
    with pytest.raises(ValueError):
        profiles.add_access_key_profile("bad name!", "a", "b")
    with pytest.raises(ValueError):
        profiles.add_role_profile("ok", "not-an-arn", "default")


def test_sso_profile_and_device_login(aws_files, monkeypatch):
    cfg, _ = aws_files
    oidc = boto3.client("sso-oidc", region_name="eu-west-1")
    sso = boto3.client("sso", region_name="eu-west-1")
    so, ss = Stubber(oidc), Stubber(sso)
    so.add_response("register_client", {"clientId": "cid", "clientSecret": "csec", "clientSecretExpiresAt": 1893456000})
    so.add_response("start_device_authorization", {"deviceCode": "dc", "userCode": "ABCD-EFGH", "verificationUri": "https://device",
                                                   "verificationUriComplete": "https://device?code=ABCD-EFGH", "expiresIn": 60, "interval": 1})
    so.add_client_error("create_token", service_error_code="AuthorizationPendingException")
    so.add_response("create_token", {"accessToken": "tok", "expiresIn": 3600, "refreshToken": "rt"})
    ss.add_response("list_accounts", {"accountList": [{"accountId": "111122223333", "accountName": "prod"}]})
    ss.add_response("list_account_roles", {"roleList": [{"roleName": "AdministratorAccess", "accountId": "111122223333"},
                                                        {"roleName": "ReadOnlyAccess", "accountId": "111122223333"}]})
    so.activate(); ss.activate()
    monkeypatch.setattr(profiles.boto3, "client", lambda name, **kw: {"sso-oidc": oidc, "sso": sso}[name])
    monkeypatch.setattr(profiles.time, "sleep", lambda s: None)
    codes = []
    token = profiles.sso_login("cost-sso", "https://my.awsapps.com/start", "eu-west-1", codes.append, open_browser=False)
    assert token == "tok" and codes[0].user_code == "ABCD-EFGH"
    import hashlib
    cache = json.loads((cfg.parent / ".aws" / "sso" / "cache" / (hashlib.sha1(b"cost-sso").hexdigest() + ".json")).read_text())
    assert cache["accessToken"] == "tok" and cache["expiresAt"].endswith("Z") and cache["refreshToken"] == "rt"
    assert profiles.sso_accounts(token, "eu-west-1") == [("111122223333", "prod", ["AdministratorAccess", "ReadOnlyAccess"])]
    profiles.add_sso_profile("cost-sso", "cost-sso", "https://my.awsapps.com/start", "eu-west-1", "111122223333", "ReadOnlyAccess")
    c = cfg.read_text()
    assert "[sso-session cost-sso]\nsso_start_url = https://my.awsapps.com/start\nsso_region = eu-west-1\n" in c
    assert "[profile cost-sso]\nsso_session = cost-sso\nsso_account_id = 111122223333\nsso_role_name = ReadOnlyAccess\n" in c


def test_tui_add_profile_with_keys(aws_files):
    import deadweight.ui as ui

    async def run():
        with mock_aws():
            app = ui.AwsCostApp()
            async with app.run_test(size=(160, 48)) as pilot:
                await pilot.pause(0.3)
                app.action_add_profile()
                await pilot.pause(0.4)
                scr = app.screen
                scr.query_one("#pf-kind").query("RadioButton")[1].value = True
                await pilot.pause(0.2)
                scr.query_one("#pf-akid").value = "AKIAEXAMPLE1234"
                scr.query_one("#pf-secret").value = "examplesecret"
                scr.query_one("#dlg-apply").press()
                for _ in range(50):
                    await pilot.pause(0.1)
                    if app.screen is not scr:
                        break
                return app.query_one("#profile").value, [str(o) for o in profiles.list_profiles()], app._exception
    value, names, exc = asyncio.run(run())
    assert exc is None
    assert value == "cost-readonly" and "cost-readonly" in names
