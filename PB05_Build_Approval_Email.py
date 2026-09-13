import html
import json
import re
from urllib.parse import urlsplit, urlunsplit


FRONTEND_BASE_URL = "http://10.10.50.30:3001"


def decode_json(value):
    current = value
    for _ in range(6):
        if isinstance(current, (dict, list)):
            return current
        if current is None:
            return {}
        if not isinstance(current, str):
            return current
        text = current.strip()
        if not text:
            return {}
        try:
            current = json.loads(text)
        except Exception:
            return current
    return current


def walk(value):
    value = decode_json(value)
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def find_value(root, names, default=""):
    wanted = {str(name).lower() for name in names}
    for item in walk(root):
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if str(key).lower() in wanted and value not in (None, "", [], {}):
                parsed = decode_json(value)
                if not isinstance(parsed, (dict, list)):
                    return parsed
    return default


def find_list(root, names):
    wanted = {str(name).lower() for name in names}
    for item in walk(root):
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if str(key).lower() not in wanted:
                continue
            parsed = decode_json(value)
            if isinstance(parsed, list):
                return [str(entry).strip() for entry in parsed if str(entry).strip()]
            if isinstance(parsed, str) and parsed.strip():
                return [
                    part.strip()
                    for part in re.split(r"[,;\n]+", parsed)
                    if part.strip()
                ]
    return []


def rewrite_frontend_url(value):
    url = str(value or "").strip()
    if not url:
        return ""

    try:
        source = urlsplit(url)
        frontend = urlsplit(FRONTEND_BASE_URL)
        if source.path.startswith("/forms/"):
            return urlunsplit(
                (
                    frontend.scheme,
                    frontend.netloc,
                    source.path,
                    source.query,
                    source.fragment
                )
            )
    except Exception:
        pass

    return url


payload = decode_json(r'''$exec''')

case_id = str(find_value(payload, ["case_id"])).strip()
campaign_id = str(find_value(payload, ["campaign_id"])).strip()
case_version = str(find_value(payload, ["case_version"])).strip()
endpoint_host = str(
    find_value(payload, ["endpoint_host", "target_host"], "UNKNOWN_ENDPOINT")
).strip()
affected_user = str(
    find_value(payload, ["affected_user", "target_user"], "UNKNOWN_USER")
).strip()
response_profile = str(
    find_value(payload, ["response_profile"], "NOT_SELECTED")
).strip()
risk_level = str(find_value(payload, ["risk_level"], "UNKNOWN")).strip()
priority = str(find_value(payload, ["priority"], "P2")).strip().upper()

approved_actions = find_list(
    payload,
    [
        "executable_actions_after_approval",
        "approval_required_actions",
        "approved_actions"
    ]
)

approve_url = rewrite_frontend_url(
    find_value(
        payload,
        ["frontend_continue", "frontend_continue_url", "continue_url", "api_continue"]
    )
)
abort_url = rewrite_frontend_url(
    find_value(
        payload,
        ["frontend_abort", "frontend_abort_url", "abort_url", "api_abort"]
    )
)

errors = []
if not case_id:
    errors.append("CASE_ID_MISSING")
if not approve_url:
    errors.append("APPROVAL_CONTINUE_URL_MISSING")
if not abort_url:
    errors.append("APPROVAL_ABORT_URL_MISSING")

action_lines = "".join(
    "<li><code>{}</code></li>".format(html.escape(action))
    for action in approved_actions
)
if not action_lines:
    action_lines = "<li>No executable action is proposed; review or escalation only.</li>"

approve_button = (
    '<a href="{}" style="display:inline-block;padding:12px 18px;'
    'background:#167d3f;color:#ffffff;text-decoration:none;'
    'border-radius:5px;font-weight:bold;">Approve and continue</a>'
).format(html.escape(approve_url, quote=True))

abort_button = (
    '<a href="{}" style="display:inline-block;padding:12px 18px;'
    'background:#a12622;color:#ffffff;text-decoration:none;'
    'border-radius:5px;font-weight:bold;margin-left:12px;">Do not execute</a>'
).format(html.escape(abort_url, quote=True))

html_body = """
<div style="font-family:Arial,sans-serif;line-height:1.5;color:#222;">
  <h2>PB05 analyst approval required</h2>
  <p><strong>Case:</strong> {case_id}<br>
     <strong>Campaign:</strong> {campaign_id}<br>
     <strong>Case version:</strong> {case_version}<br>
     <strong>Endpoint:</strong> {endpoint_host}<br>
     <strong>Affected user:</strong> {affected_user}<br>
     <strong>Risk:</strong> {risk_level}<br>
     <strong>Response profile:</strong> {response_profile}</p>
  <p><strong>Actions awaiting approval:</strong></p>
  <ul>{action_lines}</ul>
  <p>{approve_button}{abort_button}</p>
  <p style="font-size:12px;color:#666;">
    Approve only after checking that the case, endpoint, user and action set are correct.
    PB05 will still perform fresh safety validation before making any change.
  </p>
</div>
""".format(
    case_id=html.escape(case_id or "MISSING"),
    campaign_id=html.escape(campaign_id or "MISSING"),
    case_version=html.escape(case_version or "UNKNOWN"),
    endpoint_host=html.escape(endpoint_host),
    affected_user=html.escape(affected_user),
    risk_level=html.escape(risk_level),
    response_profile=html.escape(response_profile),
    action_lines=action_lines,
    approve_button=approve_button,
    abort_button=abort_button
)

output = {
    "approval_email_valid": len(errors) == 0,
    "approval_email_status": (
        "PB05_APPROVAL_EMAIL_READY" if not errors else "FAILED_CLOSED"
    ),
    "approval_email_errors": errors,
    "schema_version": "1.0",
    "helper_workflow_id": "NTF01",
    "playbook_id": "PB05",
    "case_id": case_id,
    "campaign_id": campaign_id,
    "notification_type": "PB05_ANALYST_APPROVAL_REQUEST",
    "priority": priority if priority in {"P1", "P2", "P3", "P4"} else "P2",
    "subject": "[{}] PB05 approval required - {}".format(
        priority if priority in {"P1", "P2", "P3", "P4"} else "P2",
        endpoint_host
    ),
    "html_body": html_body,
    "notification_status": "READY" if not errors else "FAILED_CLOSED",
    "approve_url_found": bool(approve_url),
    "abort_url_found": bool(abort_url),
    "executable_actions": approved_actions
}

print(json.dumps(output))
