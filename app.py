import hashlib
import re
from datetime import datetime
from pathlib import Path

import streamlit as st


MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024
SUPPORTED_FILE_EXTENSIONS = (".txt", ".py", ".json")

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# A final sentence period is allowed, but another numeric segment is not.
# The callback below still checks that every octet is between 0 and 255.
IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])"
)

ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?P<prefix>
        (?P<key_quote>["']?)
        (?P<name>
            \b(?:
                (?:[A-Za-z][A-Za-z0-9_]*_)?(?:password|passwd|pwd)
                |api[_-]key
                |secret_key
                |private_key
                |(?:[A-Za-z][A-Za-z0-9_]*_)?(?:token|secret)
            )\b
        )
        (?P=key_quote)
        (?P<separator>[ \t]*(?:=|:)[ \t]*)
    )
    (?:
        "(?P<double_value>(?:\\.|[^"\\\r\n])+)"
        |
        '(?P<single_value>(?:\\.|[^'\\\r\n])+)'
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Triple-quoted and multiline credential values are a known MVP limitation.


def sanitize_text(text):
    """Replace sensitive values and return text, counts, and a restore mapping."""
    counts = {
        "Email": 0,
        "IPv4": 0,
        "Password": 0,
        "API Key / Token": 0,
    }
    value_to_placeholder = {
        "Email": {},
        "IPv4": {},
        "Password": {},
        "API Key / Token": {},
    }
    placeholder_mapping = {}

    def placeholder_for(category, placeholder_name, value):
        """Return one stable placeholder for each unique sensitive value."""
        category_mapping = value_to_placeholder[category]

        if value not in category_mapping:
            counts[category] += 1
            placeholder = f"[{placeholder_name}_{counts[category]}]"
            category_mapping[value] = placeholder
            placeholder_mapping[placeholder] = value

        return category_mapping[value]

    def replace_assignment(match):
        variable_name = match.group("name")
        value = match.group("double_value")

        if value is not None:
            quote = '"'
        else:
            value = match.group("single_value")
            quote = "'"

        normalized_name = variable_name.lower()
        if normalized_name in {"password", "passwd", "pwd"} or (
            normalized_name.endswith(("_password", "_passwd", "_pwd"))
        ):
            category = "Password"
            placeholder_name = "PASSWORD"
        else:
            category = "API Key / Token"
            placeholder_name = "API_KEY"

        placeholder = placeholder_for(category, placeholder_name, value)
        return f'{match.group("prefix")}{quote}{placeholder}{quote}'

    def replace_email(match):
        email = match.group(0)
        return placeholder_for("Email", "EMAIL", email)

    def replace_ipv4(match):
        address = match.group(0)
        octets = address.split(".")

        if not all(0 <= int(octet) <= 255 for octet in octets):
            return address

        return placeholder_for("IPv4", "IPV4", address)

    # Redact assignments first so their contents are not counted a second time.
    sanitized = ASSIGNMENT_PATTERN.sub(replace_assignment, text)
    sanitized = EMAIL_PATTERN.sub(replace_email, sanitized)
    sanitized = IPV4_PATTERN.sub(replace_ipv4, sanitized)

    return sanitized, counts, placeholder_mapping


def privacy_risk_level(detection_counts):
    """Return the deterministic privacy risk level and its explanation."""
    credential_detected = any(
        detection_counts.get(category, 0) > 0
        for category in ("Password", "API Key / Token")
    )
    if credential_detected:
        return (
            "HIGH",
            "At least one Password or API Key / Token / Secret was detected.",
        )

    identifier_detected = any(
        detection_counts.get(category, 0) > 0
        for category in ("Email", "IPv4")
    )
    if identifier_detected:
        return (
            "MEDIUM",
            "Email or IPv4 data was detected, with no credential category detected.",
        )

    return "LOW", "No supported sensitive entities were detected."


def restore_text(text, mapping):
    """Restore only placeholders found in the current session mapping."""
    if not mapping:
        return text

    # One regex pass prevents restored values from being processed a second time.
    placeholder_pattern = re.compile(
        "|".join(re.escape(placeholder) for placeholder in mapping)
    )
    return placeholder_pattern.sub(
        lambda match: mapping[match.group(0)],
        text,
    )


def read_uploaded_file(uploaded_file):
    """Validate and decode an uploaded text file without saving it to disk."""
    if not uploaded_file.name.lower().endswith(SUPPORTED_FILE_EXTENSIONS):
        return None, "Unsupported file type. Upload a .txt, .py, or .json file."

    if uploaded_file.size > MAX_FILE_SIZE_BYTES:
        return None, "File is larger than 2 MB. Choose a smaller file."

    file_bytes = uploaded_file.getvalue()
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        return None, "File is larger than 2 MB. Choose a smaller file."

    try:
        return file_bytes.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, "Unable to read this file as UTF-8 text."


def sanitized_filename_for(source_name):
    """Build a safe download name while preserving a supported file type."""
    if not source_name:
        return "docuguard_sanitized.txt"

    base_name = source_name.replace("\\", "/").split("/")[-1]
    if "." not in base_name:
        return "docuguard_sanitized.txt"

    stem, extension = base_name.rsplit(".", 1)
    extension = extension.lower()
    if f".{extension}" not in SUPPORTED_FILE_EXTENSIONS:
        return "docuguard_sanitized.txt"

    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    if not safe_stem:
        safe_stem = "file"

    return f"sanitized_{safe_stem}.{extension}"


def mime_type_for(filename):
    """Return the download MIME type for a sanitized text file."""
    if filename.lower().endswith(".py"):
        return "text/x-python"
    if filename.lower().endswith(".json"):
        return "application/json"
    return "text/plain"


def read_local_text_file(file_path):
    """Read a supported local file as UTF-8 text without executing it."""
    cleaned_path = file_path.strip().strip('"')
    if not cleaned_path:
        return None, None, None, "Enter a local file path."

    path = Path(cleaned_path)
    if path.suffix.lower() not in SUPPORTED_FILE_EXTENSIONS:
        return (
            None,
            None,
            None,
            "Unsupported file type. Choose a .txt, .py, or .json file.",
        )

    try:
        if not path.is_file():
            return None, None, None, "The local file could not be found."

        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            return None, None, None, "File is larger than 2 MB. Choose a smaller file."

        file_bytes = path.read_bytes()
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            return None, None, None, "File is larger than 2 MB. Choose a smaller file."

        modified_time = path.stat().st_mtime
    except OSError:
        return None, None, None, "The local file could not be read."

    try:
        text = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, None, None, "Unable to read this file as UTF-8 text."

    try:
        resolved_path = str(path.resolve())
    except OSError:
        resolved_path = str(path)

    return text, resolved_path, modified_time, None


def content_fingerprint(text):
    """Return a SHA-256 fingerprint for decoded text content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def time_label(timestamp=None):
    """Format a local timestamp for the Freshness Guard status panel."""
    if timestamp is None:
        moment = datetime.now().astimezone()
    else:
        moment = datetime.fromtimestamp(timestamp).astimezone()
    return moment.strftime("%Y-%m-%d %H:%M:%S %Z")


def store_sanitized_result(text, source_name, source_fingerprint=None):
    """Run the existing sanitizer and store its current-session results."""
    sanitized_text, detection_counts, placeholder_mapping = sanitize_text(text)
    st.session_state["placeholder_mapping"] = placeholder_mapping
    st.session_state["sanitized_output"] = sanitized_text
    st.session_state["sanitized_filename"] = sanitized_filename_for(source_name)
    st.session_state["detection_counts"] = detection_counts

    if source_fingerprint is not None:
        st.session_state["monitored_sanitized_fingerprint"] = source_fingerprint


def reset_monitoring_state():
    """Stop monitoring when the user switches back to snapshot input."""
    st.session_state["monitored_file_path"] = None
    st.session_state["monitored_file_name"] = None
    st.session_state["monitored_latest_fingerprint"] = None
    st.session_state["monitored_sanitized_fingerprint"] = None
    st.session_state["monitored_modified_time"] = None
    st.session_state["monitored_last_checked"] = None
    st.session_state["freshness_status"] = "NOT MONITORED"
    st.session_state["freshness_notice"] = None
    st.session_state["freshness_notice_level"] = "info"
    st.session_state["monitor_action_error"] = None
    st.session_state["monitored_download_ready"] = False


def set_freshness_notice(message, level="info"):
    """Store a short Freshness Guard message for the current session."""
    st.session_state["freshness_notice"] = message
    st.session_state["freshness_notice_level"] = level


def freshness_event_text(status, notice):
    """Turn the existing monitor notice into a concise UI event label."""
    event_labels = {
        "Monitoring started — latest file version sanitized.": (
            "File loaded and monitored"
        ),
        "✓ No changes detected": "No changes detected",
        "Change detected — latest file version loaded": (
            "Change detected → latest version reprocessed"
        ),
        "✓ Latest version verified for download": "No changes detected",
    }

    if notice in event_labels:
        return event_labels[notice]
    if status == "UNAVAILABLE":
        return "Monitored file unavailable"
    if notice and "UTF-8" in notice:
        return "File rejected — UTF-8 decode error"
    if notice and "larger than 2 MB" in notice:
        return "File rejected — exceeds 2 MB limit"
    if notice and "Unsupported file type" in notice:
        return "File rejected — unsupported file type"
    if notice:
        return "File rejected — " + notice
    return "No file monitored yet"


def load_monitored_file(file_path):
    """Load, sanitize, and begin monitoring a local text file."""
    text, resolved_path, modified_time, error = read_local_text_file(file_path)
    if error:
        set_freshness_notice(error, "error")
        return error

    fingerprint = content_fingerprint(text)
    file_name = Path(resolved_path).name

    st.session_state["monitored_file_path"] = resolved_path
    st.session_state["monitored_file_name"] = file_name
    st.session_state["monitored_latest_fingerprint"] = fingerprint
    st.session_state["monitored_modified_time"] = modified_time
    st.session_state["monitored_last_checked"] = time_label()
    st.session_state["freshness_status"] = "FRESH"
    st.session_state["monitor_action_error"] = None
    st.session_state["monitored_download_ready"] = False
    st.session_state["source_text"] = text
    st.session_state["active_input_name"] = file_name

    store_sanitized_result(text, file_name, fingerprint)
    set_freshness_notice(
        "Monitoring started — latest file version sanitized.", "success"
    )
    return None


def check_monitored_file():
    """Check the monitored file and re-sanitize it when its content changes."""
    file_path = st.session_state.get("monitored_file_path")
    if not file_path:
        return "No local file is currently monitored."

    text, resolved_path, modified_time, error = read_local_text_file(file_path)
    st.session_state["monitored_last_checked"] = time_label()

    if error:
        st.session_state["freshness_status"] = "UNAVAILABLE"
        st.session_state["monitor_action_error"] = error
        st.session_state["monitored_download_ready"] = False
        set_freshness_notice(error, "error")
        return error

    fingerprint = content_fingerprint(text)
    st.session_state["monitored_latest_fingerprint"] = fingerprint
    st.session_state["monitored_modified_time"] = modified_time
    st.session_state["monitor_action_error"] = None
    st.session_state["monitored_download_ready"] = False

    if fingerprint == st.session_state.get("monitored_sanitized_fingerprint"):
        st.session_state["freshness_status"] = "FRESH"
        set_freshness_notice("✓ No changes detected", "success")
        return None

    file_name = Path(resolved_path).name
    st.session_state["freshness_status"] = "CHANGE DETECTED / REFRESHED"
    st.session_state["source_text"] = text
    st.session_state["active_input_name"] = file_name
    store_sanitized_result(text, file_name, fingerprint)
    st.session_state["freshness_status"] = "FRESH"
    set_freshness_notice(
        "Change detected — latest file version loaded", "success"
    )
    return None


def refresh_monitored_source_before_sanitize():
    """Load the latest monitored source before the Sanitize action runs."""
    file_path = st.session_state.get("monitored_file_path")
    st.session_state["monitor_action_error"] = None
    if not file_path:
        return

    text, resolved_path, modified_time, error = read_local_text_file(file_path)
    st.session_state["monitored_last_checked"] = time_label()
    st.session_state["monitored_download_ready"] = False

    if error:
        st.session_state["freshness_status"] = "UNAVAILABLE"
        st.session_state["monitor_action_error"] = error
        set_freshness_notice(error, "error")
        return

    fingerprint = content_fingerprint(text)
    file_name = Path(resolved_path).name
    changed = fingerprint != st.session_state.get(
        "monitored_sanitized_fingerprint"
    )
    st.session_state["source_text"] = text
    st.session_state["active_input_name"] = file_name
    st.session_state["monitored_latest_fingerprint"] = fingerprint
    st.session_state["monitored_modified_time"] = modified_time

    if changed:
        set_freshness_notice(
            "Change detected — latest file version loaded", "success"
        )


def prepare_monitored_download():
    """Verify and refresh a monitored result before enabling its download."""
    file_path = st.session_state.get("monitored_file_path")
    if not file_path:
        return

    text, resolved_path, modified_time, error = read_local_text_file(file_path)
    st.session_state["monitored_last_checked"] = time_label()

    if error:
        st.session_state["freshness_status"] = "UNAVAILABLE"
        st.session_state["monitor_action_error"] = error
        st.session_state["monitored_download_ready"] = False
        set_freshness_notice(error, "error")
        return

    fingerprint = content_fingerprint(text)
    file_name = Path(resolved_path).name
    st.session_state["monitored_latest_fingerprint"] = fingerprint
    st.session_state["monitored_modified_time"] = modified_time
    st.session_state["monitor_action_error"] = None

    if fingerprint != st.session_state.get("monitored_sanitized_fingerprint"):
        st.session_state["source_text"] = text
        st.session_state["active_input_name"] = file_name
        store_sanitized_result(text, file_name, fingerprint)
        set_freshness_notice(
            "Change detected — latest file version loaded", "success"
        )
    else:
        set_freshness_notice("✓ Latest version verified for download", "success")

    st.session_state["freshness_status"] = "FRESH"
    st.session_state["monitored_download_ready"] = True


def consume_prepared_download():
    """Require a new freshness check before another monitored download."""
    st.session_state["monitored_download_ready"] = False


def clear_active_file():
    """Mark the text area as manual input after the user changes a widget."""
    st.session_state["active_input_name"] = None
    reset_monitoring_state()


def clear_uploaded_file_selection():
    """Keep a selected upload inactive until the user chooses to use it."""
    st.session_state["active_input_name"] = None


st.set_page_config(page_title="DocuGuard", layout="wide")
st.session_state.setdefault("placeholder_mapping", {})
st.session_state.setdefault("source_text", "")
st.session_state.setdefault("active_input_name", None)
st.session_state.setdefault("sanitized_output", None)
st.session_state.setdefault("sanitized_filename", None)
st.session_state.setdefault("detection_counts", None)
st.session_state.setdefault("monitored_file_path", None)
st.session_state.setdefault("monitored_file_name", None)
st.session_state.setdefault("monitored_latest_fingerprint", None)
st.session_state.setdefault("monitored_sanitized_fingerprint", None)
st.session_state.setdefault("monitored_modified_time", None)
st.session_state.setdefault("monitored_last_checked", None)
st.session_state.setdefault("freshness_status", "NOT MONITORED")
st.session_state.setdefault("freshness_notice", None)
st.session_state.setdefault("freshness_notice_level", "info")
st.session_state.setdefault("monitor_action_error", None)
st.session_state.setdefault("monitored_download_ready", False)

st.html(
    """
    <style>
        :root {
            color-scheme: dark;
            font-synthesis: none;
        }
        [data-testid="stMainBlockContainer"] {
            max-width: 1080px;
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }
        [data-testid="stAppViewContainer"] {
            font-size: 1rem;
        }
        [data-testid="stAppViewContainer"] h1,
        [data-testid="stAppViewContainer"] h2,
        [data-testid="stAppViewContainer"] h3,
        [data-testid="stAppViewContainer"] h4 {
            line-height: 1.2;
            letter-spacing: -0.012em;
            overflow-wrap: anywhere;
            text-wrap: balance;
        }
        [data-testid="stAppViewContainer"] p,
        [data-testid="stAppViewContainer"] label {
            line-height: 1.5;
        }
        [data-testid="stCaptionContainer"] p {
            color: #9fb0c2;
            font-size: 0.82rem;
            line-height: 1.4;
            margin: 0;
            overflow-wrap: anywhere;
        }
        [data-testid="stWidgetLabel"] p {
            line-height: 1.35;
            white-space: normal;
        }
        [data-testid="stMetric"] {
            min-width: 0;
        }
        [data-testid="stMetricLabel"] {
            align-items: flex-start;
            min-height: 2.35rem;
        }
        [data-testid="stMetricLabel"] p,
        [data-testid="stMetricValue"] {
            line-height: 1.25;
            overflow-wrap: anywhere;
            white-space: normal;
        }
        [data-testid="stAlert"] {
            align-items: flex-start;
        }
        [data-testid="stAlert"] p {
            line-height: 1.45;
            overflow-wrap: anywhere;
        }
        [data-testid="stButton"] button,
        [data-testid="stDownloadButton"] button {
            min-height: 2.75rem;
            line-height: 1.2;
            white-space: normal;
        }
        .st-key-hero { padding: 0 0 0.25rem; }
        .dg-eyebrow {
            color: #67d9f3;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.16em;
            margin-bottom: 0.35rem;
        }
        .dg-brand-lockup {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.45rem;
        }
        .dg-monogram {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 2.6rem;
            height: 2.6rem;
            color: #dff8ff;
            background: #0b5f8a;
            border: 1px solid #35c3e5;
            border-radius: 0.65rem;
            font-weight: 800;
            letter-spacing: 0.04em;
        }
        .dg-wordmark {
            color: #f3f7fb;
            font-size: clamp(1.85rem, 5vw, 2.25rem);
            font-weight: 750;
            line-height: 1;
        }
        .st-key-privacy_engine {
            background: #0f1720;
            border-color: #2a3b4d;
            border-radius: 0.8rem;
        }
        .dg-engine-title {
            color: #9fb0c2;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            margin-bottom: 0.55rem;
        }
        .dg-active-line {
            display: flex;
            align-items: center;
            gap: 0.45rem;
            color: #7ee2b8;
            font-size: 0.78rem;
            font-weight: 750;
            letter-spacing: 0.08em;
        }
        .dg-active-dot {
            width: 0.55rem;
            height: 0.55rem;
            background: #34d399;
            border-radius: 50%;
            box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.35);
            animation: dg-pulse 2.2s ease-out infinite;
        }
        @keyframes dg-pulse {
            0%, 45% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.3); }
            75%, 100% { box-shadow: 0 0 0 0.4rem rgba(52, 211, 153, 0); }
        }
        @media (prefers-reduced-motion: reduce) {
            .dg-active-dot { animation: none; }
        }
        .st-key-workflow_strip {
            background: #0f1720;
            border: 1px solid #30445a;
            border-radius: 0.75rem;
            padding: 0.5rem 0.8rem;
            margin-bottom: 0.75rem;
            overflow: hidden;
        }
        .st-key-restore_workflow {
            background: #0d141c;
            border: 1px solid #233140;
            border-radius: 0.7rem;
            padding: 0.4rem 0.65rem;
            margin-top: 0.5rem;
            margin-bottom: 0.55rem;
            opacity: 0.9;
            overflow: hidden;
        }
        .st-key-input_section,
        .st-key-restore_section {
            background: #111821;
            border-radius: 0.75rem;
            overflow: hidden;
        }
        .st-key-freshness_guard,
        .st-key-freshness_status {
            background: #0d151d;
            border-color: #2a3b4d;
            border-radius: 0.7rem;
            overflow: hidden;
        }
        .st-key-detects_row {
            padding: 0.15rem 0 0.45rem;
        }
        .st-key-primary_sanitize button {
            min-height: 3rem;
            min-width: 15rem;
            font-weight: 700;
            color: #f8fafc;
            background: #0878b9;
            border-color: #22b8df;
        }
        .st-key-primary_sanitize button:hover {
            color: #ffffff;
            background: #096b9f;
            border-color: #67d9f3;
        }
        .st-key-privacy_report {
            background: #0f1720;
            border: 1px solid #30445a;
            border-left: 4px solid #22b8cf;
            border-radius: 0.75rem;
            overflow: hidden;
        }
        .st-key-privacy_metrics,
        .st-key-category_counts {
            align-items: stretch;
            gap: 0.65rem;
        }
        .st-key-privacy_metrics [data-testid="stMetric"],
        .st-key-category_counts [data-testid="stMetric"] {
            flex: 1 1 10.5rem;
        }
        .st-key-original_panel {
            background: #151216;
            border: 1px solid #743840;
            border-left: 4px solid #ef6b73;
            border-radius: 0.75rem;
            overflow: hidden;
        }
        .st-key-protected_panel {
            background: #0d171b;
            border: 1px solid #266577;
            border-left: 4px solid #22b8cf;
            border-radius: 0.75rem;
            overflow: hidden;
        }
        .st-key-footer_note {
            margin-top: 1.5rem;
            padding-top: 1rem;
            border-top: 1px solid #273241;
        }
        @media (max-width: 640px) {
            [data-testid="stMainBlockContainer"] {
                padding-left: 0.85rem;
                padding-right: 0.85rem;
                padding-top: 1rem;
            }
            .dg-brand-lockup {
                gap: 0.6rem;
            }
            .dg-monogram {
                width: 2.25rem;
                height: 2.25rem;
                flex: 0 0 2.25rem;
            }
            .st-key-workflow_strip [data-testid="stMarkdownContainer"],
            .st-key-restore_workflow [data-testid="stMarkdownContainer"] {
                display: none;
            }
            .st-key-primary_sanitize,
            .st-key-primary_sanitize button,
            .st-key-prepare_monitored_download,
            .st-key-prepare_monitored_download button,
            .st-key-download_sanitized,
            .st-key-download_sanitized button {
                min-width: 0;
                width: 100%;
            }
            .st-key-privacy_metrics [data-testid="stMetric"],
            .st-key-category_counts [data-testid="stMetric"] {
                flex-basis: 100%;
            }
        }
    </style>
    """
)

with st.container(key="hero"):
    hero_copy, hero_status = st.columns([1.45, 1], vertical_alignment="center")

    with hero_copy:
        st.html(
            """
            <div class="dg-eyebrow">DOCUGUARD</div>
            <div class="dg-brand-lockup">
                <span class="dg-monogram">DG</span>
                <span class="dg-wordmark">DocuGuard</span>
            </div>
            """
        )
        st.subheader("Privacy Layer for AI Workflows")
        st.write(
            "Protect sensitive code, credentials, logs and documents before "
            "sharing them with cloud AI."
        )

    with hero_status:
        with st.container(border=True, key="privacy_engine"):
            st.html(
                """
                <div class="dg-engine-title">PRIVACY ENGINE</div>
                <div class="dg-active-line">
                    <span class="dg-active-dot"></span>
                    <span>ACTIVE</span>
                </div>
                """
            )
            st.markdown(
                "**External AI/API Requests:** 0  \n"
                "**Mapping:** SESSION ONLY  \n"
                "**Supported:** TXT · PY · JSON"
            )

with st.container(
    horizontal=True,
    vertical_alignment="center",
    gap="small",
    wrap=True,
    key="workflow_strip",
):
    st.badge("INPUT", color="gray")
    st.markdown("→")
    st.badge("DETECT", color="blue")
    st.markdown("→")
    st.badge("ANONYMIZE", color="blue")
    st.markdown("→")
    st.badge("AI-SAFE", color="green")
    st.markdown("→")
    st.badge("RESTORE", color="gray")

st.subheader("1. Add Content")
st.caption("Paste content below or upload a supported text file.")

with st.container(border=True, key="input_section"):
    with st.container(
        horizontal=True,
        vertical_alignment="center",
        gap="small",
        wrap=True,
        key="detects_row",
    ):
        st.caption("DETECTS")
        st.badge("Email", color="gray")
        st.badge("IPv4", color="gray")
        st.badge("Passwords", color="gray")
        st.badge("API Keys", color="gray")
        st.badge("Tokens", color="gray")

    with st.container(border=True, key="freshness_guard"):
        st.markdown("#### Freshness Guard — Local / self-hosted mode")
        st.info(
            "Freshness Guard monitors files accessible to the running "
            "Streamlit process. The hosted demo cannot access files on your "
            "computer. Browser uploads are snapshots and cannot be monitored "
            "for later changes.",
            icon=":material/info:",
        )
        monitored_path_input = st.text_input(
            "Local / self-hosted file path",
            placeholder=r"C:\Projects\app\config.py",
            key="monitored_path_input",
        )

        with st.container(horizontal=True, gap="small", wrap=True):
            st.button(
                "Load & Monitor",
                key="load_monitored_file",
                on_click=load_monitored_file,
                args=(monitored_path_input,),
            )
            if st.session_state["monitored_file_path"]:
                st.button(
                    "Check for Changes",
                    key="check_monitored_file",
                    on_click=check_monitored_file,
                )

        status = st.session_state["freshness_status"]
        current_state = (
            status
            if status in {"NOT MONITORED", "FRESH", "UNAVAILABLE"}
            else "FRESH"
        )
        status_color = {
            "FRESH": "green",
            "UNAVAILABLE": "red",
            "NOT MONITORED": "gray",
        }[current_state]
        notice = st.session_state["freshness_notice"]
        notice_level = st.session_state["freshness_notice_level"]
        last_event = freshness_event_text(current_state, notice)

        with st.container(border=True, key="freshness_status"):
            state_column, event_column = st.columns(
                [1, 2], vertical_alignment="top"
            )
            with state_column:
                st.caption("Current State")
                st.badge(current_state, color=status_color)
            with event_column:
                st.caption("Last Event")
                if notice_level == "error":
                    st.markdown(f":red[**{last_event}**]")
                elif current_state == "FRESH":
                    st.markdown(f":green[**{last_event}**]")
                else:
                    st.markdown(f"**{last_event}**")

            if st.session_state["monitored_file_name"]:
                st.caption(
                    f'File: {st.session_state["monitored_file_name"]}'
                )

            last_checked = (
                st.session_state["monitored_last_checked"] or "—"
            )
            modified_time = st.session_state["monitored_modified_time"]
            last_modified = (
                time_label(modified_time) if modified_time is not None else "—"
            )
            checked_column, modified_column = st.columns(2)
            checked_column.caption(f"Last Checked: {last_checked}")
            modified_column.caption(f"Last Modified: {last_modified}")

    uploaded_file = st.file_uploader(
        "Upload a file (optional)",
        type=["txt", "py", "json"],
        key="uploaded_file",
        on_change=clear_uploaded_file_selection,
        max_upload_size=2,
    )
    st.caption(
        "Browser uploads are sent to this Streamlit app for in-memory "
        "processing. DocuGuard does not forward them to an external AI/API."
    )

    if uploaded_file is not None:
        uploaded_text, upload_error = read_uploaded_file(uploaded_file)

        if upload_error:
            st.error(upload_error)
        else:
            st.caption(
                f"Selected file: {uploaded_file.name} "
                f"({uploaded_file.size:,} bytes)"
            )
            st.caption("Preview (first 500 characters)")
            preview = uploaded_text[:500] or "(File is empty.)"
            st.code(preview, language=None)

            if st.button("Use Uploaded File"):
                reset_monitoring_state()
                st.session_state["source_text"] = uploaded_text
                st.session_state["active_input_name"] = uploaded_file.name

    if st.session_state["active_input_name"]:
        if st.session_state["monitored_file_path"]:
            st.success(
                "Active input: monitored local file "
                f'"{st.session_state["active_input_name"]}"'
            )
        else:
            st.success(
                "Active input: uploaded file "
                f'"{st.session_state["active_input_name"]}"'
            )

    st.caption("OR PASTE CONTENT")
    source_text = st.text_area(
        "Source code, logs, credentials, or text",
        height=260,
        placeholder="Paste sensitive content here...",
        key="source_text",
        on_change=clear_active_file,
    )

with st.container(horizontal=True, wrap=True, key="primary_action"):
    sanitize_clicked = st.button(
        "Sanitize & Protect",
        type="primary",
        key="primary_sanitize",
        width="content",
        on_click=refresh_monitored_source_before_sanitize,
    )

if sanitize_clicked:
    monitor_error = st.session_state.get("monitor_action_error")
    if monitor_error:
        st.warning(
            "The monitored file is unavailable, so it was not sanitized. "
            + monitor_error
        )
    elif not source_text.strip():
        st.warning("Enter some text to sanitize.")
    else:
        with st.spinner(
            "Scanning in this Streamlit session for sensitive data...",
            show_time=False,
        ):
            source_fingerprint = None
            if st.session_state["monitored_file_path"]:
                source_fingerprint = st.session_state[
                    "monitored_latest_fingerprint"
                ]

            store_sanitized_result(
                source_text,
                st.session_state["active_input_name"],
                source_fingerprint,
            )
        if st.session_state["monitored_file_path"]:
            st.session_state["freshness_status"] = "FRESH"
            st.session_state["monitored_download_ready"] = False

detection_counts = st.session_state.get("detection_counts")
monitored_result_is_current = (
    not st.session_state["monitored_file_path"]
    or (
        st.session_state["freshness_status"] == "FRESH"
        and st.session_state["monitored_latest_fingerprint"]
        == st.session_state["monitored_sanitized_fingerprint"]
    )
)

if detection_counts is not None and monitored_result_is_current:
    total_entities = sum(detection_counts.values())
    risk_level, risk_explanation = privacy_risk_level(detection_counts)
    risk_color = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}[
        risk_level
    ]

    with st.container(border=True, key="privacy_report"):
        st.subheader("2. Privacy Report")
        st.caption("EXPLAINABLE SESSION ASSESSMENT")

        risk_column, explanation_column = st.columns(
            [1, 2.4], vertical_alignment="center"
        )
        with risk_column:
            st.caption("RISK LEVEL")
            st.badge(risk_level, color=risk_color)
        with explanation_column:
            st.caption("WHY THIS LEVEL")
            st.markdown(f"**{risk_explanation}**")

        with st.container(
            horizontal=True,
            gap="small",
            wrap=True,
            key="privacy_metrics",
        ):
            st.metric(
                "Total sensitive entities detected",
                total_entities,
                border=True,
            )
            st.metric("Session Mapping", "Session only", border=True)
            st.metric("External AI/API Requests", 0, border=True)

        st.caption("DETECTED CATEGORIES")
        with st.container(
            horizontal=True,
            gap="small",
            wrap=True,
            key="category_counts",
        ):
            for category, count in detection_counts.items():
                st.metric(category, count, border=True)

if (
    st.session_state["sanitized_output"] is not None
    and monitored_result_is_current
):
    st.subheader("3. Sanitized Result")
    original_column, protected_column = st.columns(2)

    with original_column:
        with st.container(border=True, key="original_panel"):
            st.markdown("#### Original")
            st.badge("SENSITIVE", color="red")
            st.code(source_text, language=None)

    with protected_column:
        with st.container(border=True, key="protected_panel"):
            st.markdown("#### Protected")
            st.badge("AI-SAFE", color="green")
            st.code(st.session_state["sanitized_output"], language=None)
            if st.session_state["monitored_file_path"]:
                st.caption(
                    "Verify the latest local version before each monitored "
                    "download."
                )
                st.button(
                    "Prepare Latest Download",
                    key="prepare_monitored_download",
                    on_click=prepare_monitored_download,
                )
                if st.session_state["monitored_download_ready"]:
                    st.download_button(
                        "Download Sanitized File",
                        data=st.session_state["sanitized_output"],
                        file_name=st.session_state["sanitized_filename"],
                        mime=mime_type_for(
                            st.session_state["sanitized_filename"]
                        ),
                        key="download_sanitized",
                        on_click=consume_prepared_download,
                    )
            else:
                st.download_button(
                    "Download Sanitized File",
                    data=st.session_state["sanitized_output"],
                    file_name=st.session_state["sanitized_filename"],
                    mime=mime_type_for(st.session_state["sanitized_filename"]),
                    key="download_sanitized",
                    on_click="ignore",
                )
elif (
    st.session_state["sanitized_output"] is not None
    and st.session_state["monitored_file_path"]
):
    st.warning(
        "The monitored source is unavailable or newer than the current "
        "sanitized result. Check for changes before using or downloading it."
    )

with st.container(
    horizontal=True,
    vertical_alignment="center",
    gap="small",
    wrap=True,
    key="restore_workflow",
):
    st.badge("Sanitized Prompt", color="blue")
    st.markdown("→")
    st.badge("External AI", color="gray")
    st.markdown("→")
    st.badge("Placeholder Response", color="blue")
    st.markdown("→")
    st.badge("Session Restore", color="green")

st.subheader("4. Restore AI Response")
with st.container(border=True, key="restore_section"):
    st.caption(
        "Paste the AI response containing DocuGuard placeholders to restore "
        "your original values within this Streamlit session."
    )
    st.caption(
        "🔒 Restoration uses only the temporary mapping stored in this session."
    )

    ai_response = st.text_area(
        "AI response",
        height=200,
        placeholder="Paste an AI response with DocuGuard placeholders here...",
    )

    if st.button("Restore Original Values", key="restore_original_values"):
        current_mapping = st.session_state.get("placeholder_mapping", {})

        if not current_mapping:
            st.warning(
                "Sanitize some content first to create a restoration mapping."
            )
        elif not ai_response.strip():
            st.warning("Enter an AI response to restore.")
        else:
            restored_text = restore_text(ai_response, current_mapping)
            st.success("✓ Original values restored in this session")
            st.subheader("Restored Response")
            st.code(restored_text, language=None)

with st.container(key="footer_note"):
    st.markdown("**DocuGuard · Session-scoped privacy for AI workflows**")
    st.caption("Built for Grevix AfterCode")
    st.caption(
        "DocuGuard makes no outbound AI/API requests."
    )
