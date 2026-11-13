"""Deploy the Wazuh rules bundle to a Wazuh manager through the Wazuh API.

Usage:
  python scripts/deploy_wazuh_api.py out/wazuh/sigma_rules_bundle.xml

Environment variables:
  WAZUH_API_URL         e.g. https://10.1.0.71:55000   (required)
  WAZUH_API_USER        API user, e.g. wazuh-wui        (required)
  WAZUH_API_PASSWORD    API password                    (required)
  WAZUH_API_VERIFY_TLS  set to "true" to verify the server certificate.
                        Off by default because Wazuh ships a self-signed certificate.

What it does:
  log in -> back up the current rules file -> upload the bundle -> ask Wazuh to validate
  -> if invalid: put the old file back (or delete the new one) and exit 1
  -> restart the manager -> wait until wazuh-analysisd is running again.
Standard library only, nothing to install.
"""
import base64
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

REMOTE_FILE = "sigma_rules.xml"          # saved by Wazuh in /var/ossec/etc/rules/
RESTART_GRACE = int(os.environ.get("WAZUH_RESTART_GRACE", "15"))   # seconds before polling
POLL_SECONDS = int(os.environ.get("WAZUH_POLL_SECONDS", "5"))
RESTART_TIMEOUT = int(os.environ.get("WAZUH_RESTART_TIMEOUT", "240"))


class ApiError(Exception):
    pass


def die(msg):
    print(f"::error::{msg}")
    sys.exit(1)


class Api:
    def __init__(self, url, user, password, verify_tls):
        self.url = url.rstrip("/")
        self.user, self.password = user, password
        self.token = None
        self.ctx = None
        if self.url.startswith("https://") and not verify_tls:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method, path, body=None, headers=None, auth=None, timeout=60):
        hdrs = dict(headers or {})
        if auth:
            hdrs["Authorization"] = auth
        elif self.token:
            hdrs["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:      # 4xx/5xx still carry a useful body
            return e.code, e.read().decode("utf-8", "replace")

    def json(self, method, path, body=None, headers=None):
        status, text = self.request(method, path, body, headers)
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        return status, data, text

    def login(self):
        basic = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        status, text = self.request("POST", "/security/user/authenticate?raw=true",
                                    auth="Basic " + basic)
        if status != 200 or not text.startswith("eyJ"):
            raise ApiError(f"Wazuh API login failed (HTTP {status}): {text[:200]}")
        self.token = text.strip()


def api_ok(status, data):
    return status in (200, 202) and isinstance(data, dict) and data.get("error") == 0


def current_rules_file(api):
    """Text of the rules file now on the server, or None if there is none.
    Stops the deploy if the file exists but cannot be read: no backup, no overwrite."""
    status, data, text = api.json("GET", f"/rules/files?filename={REMOTE_FILE}")
    if not api_ok(status, data):
        raise ApiError(f"could not check for an existing {REMOTE_FILE} (HTTP {status}): {text[:300]}")
    if data["data"].get("total_affected_items", 0) == 0:
        return None
    status, text = api.request("GET", f"/rules/files/{REMOTE_FILE}?raw=true&relative_dirname=etc/rules")
    if status != 200 or not text.lstrip().startswith("<"):
        raise ApiError(f"{REMOTE_FILE} exists but could not be backed up (HTTP {status}): "
                       f"{text[:300]}. Nothing was changed.")
    return text


def upload(api, content):
    status, data, text = api.json("PUT", f"/rules/files/{REMOTE_FILE}?overwrite=true", content,
                                  {"Content-Type": "application/octet-stream"})
    return api_ok(status, data), text


def validation(api):
    status, data, text = api.json("GET", "/manager/configuration/validation")
    if api_ok(status, data):
        items = data.get("data", {}).get("affected_items", [])
        if items and all(i.get("status") == "OK" for i in items):
            return True, text
    return False, text


def roll_back(api, backup):
    if backup is None:
        status, data, text = api.json("DELETE", f"/rules/files/{REMOTE_FILE}")
        what = f"deleted the new {REMOTE_FILE} (there was none before)"
    else:
        ok, text = upload(api, backup.encode("utf-8"))
        status, data = (200, {"error": 0}) if ok else (500, None)
        what = f"restored the previous {REMOTE_FILE}"
    if status == 200 and isinstance(data, dict) and data.get("error") == 0:
        print(f"Rolled back: {what}.")
    else:
        print(f"::error::Rollback FAILED, fix {REMOTE_FILE} on the server by hand: {text[:300]}")


def restart_and_wait(api):
    status, data, text = api.json("PUT", "/manager/restart")
    if not api_ok(status, data):
        raise ApiError(f"restart request failed (HTTP {status}): {text[:300]}")
    print(f"Restart requested, waiting up to {RESTART_TIMEOUT}s for the manager...")
    time.sleep(RESTART_GRACE)                    # let the old process go down first
    deadline = time.time() + RESTART_TIMEOUT
    while time.time() < deadline:
        try:
            api.login()                          # the API restarts too, so log in again
            status, data, _ = api.json("GET", "/manager/status")
            items = data["data"]["affected_items"]
            if status == 200 and items and items[0].get("wazuh-analysisd") == "running":
                return True
        except (ApiError, OSError, ValueError, KeyError, TypeError):
            pass                                 # manager still coming back up
        time.sleep(POLL_SECONDS)
    return False


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    bundle = pathlib.Path(sys.argv[1])
    if not bundle.is_file():
        die(f"{bundle} not found - did the conversion step run?")
    content = bundle.read_bytes()
    rule_count = content.count(b"<rule ")
    if rule_count == 0:
        die(f"{bundle} contains no <rule> elements, refusing to deploy an empty file")

    missing = [v for v in ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
               if not os.environ.get(v)]
    if missing:
        die("missing settings: " + ", ".join(missing))
    api = Api(os.environ["WAZUH_API_URL"], os.environ["WAZUH_API_USER"],
              os.environ["WAZUH_API_PASSWORD"],
              os.environ.get("WAZUH_API_VERIFY_TLS", "").lower() == "true")

    try:
        api.login()
        print("Logged in to the Wazuh API.")
        backup = current_rules_file(api)
        print("Backed up the current rules file." if backup is not None
              else f"No existing {REMOTE_FILE} on the server.")

        ok, text = upload(api, content)
        if not ok:
            die(f"Wazuh rejected the upload: {text[:500]}")
        print(f"Uploaded {REMOTE_FILE} ({rule_count} rules).")

        ok, text = validation(api)
        if not ok:
            print(f"::error::Wazuh says the rules are not valid: {text[:500]}")
            roll_back(api, backup)
            sys.exit(1)
        print("Wazuh validated the rules (status OK).")

        if not restart_and_wait(api):
            die("the manager did not report wazuh-analysisd running after the restart; "
                "check it on the server")
        print(f"Done: {rule_count} rules deployed and the manager is running.")
    except ApiError as e:
        die(str(e))


if __name__ == "__main__":
    main()
