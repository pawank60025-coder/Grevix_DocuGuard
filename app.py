import re

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


def clear_active_file():
    """Mark the text area as manual input after the user changes a widget."""
    st.session_state["active_input_name"] = None


st.set_page_config(page_title="DocuGuard", layout="wide")
st.session_state.setdefault("placeholder_mapping", {})
st.session_state.setdefault("source_text", "")
st.session_state.setdefault("active_input_name", None)
st.session_state.setdefault("sanitized_output", None)
st.session_state.setdefault("sanitized_filename", None)

st.html(
    """
    <style>
        :root { color-scheme: dark; }
        [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
            background: #0b1016;
        }
        [data-testid="stMainBlockContainer"] {
            max-width: 1080px;
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }
        [data-testid="stAppViewContainer"] {
            color: #e6edf3;
        }
        [data-testid="stAppViewContainer"] h1,
        [data-testid="stAppViewContainer"] h2,
        [data-testid="stAppViewContainer"] h3,
        [data-testid="stAppViewContainer"] p,
        [data-testid="stAppViewContainer"] label {
            color: #e6edf3;
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
            font-size: 2.25rem;
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
        }
        .st-key-restore_workflow {
            background: #0d141c;
            border: 1px solid #233140;
            border-radius: 0.7rem;
            padding: 0.4rem 0.65rem;
            margin-top: 0.5rem;
            margin-bottom: 0.55rem;
            opacity: 0.9;
        }
        .st-key-input_section,
        .st-key-restore_section {
            background: #111821;
            border-radius: 0.75rem;
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
        .st-key-protection_status {
            background: #0e211c;
            border: 1px solid #236a53;
            border-left: 4px solid #34d399;
            border-radius: 0.75rem;
        }
        .st-key-original_panel {
            background: #151216;
            border: 1px solid #743840;
            border-left: 4px solid #ef6b73;
            border-radius: 0.75rem;
        }
        .st-key-protected_panel {
            background: #0d171b;
            border: 1px solid #266577;
            border-left: 4px solid #22b8cf;
            border-radius: 0.75rem;
        }
        .st-key-footer_note {
            margin-top: 1.5rem;
            padding-top: 1rem;
            border-top: 1px solid #273241;
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
        st.subheader("Local Privacy Layer for AI Workflows")
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
                "**Processing:** LOCAL  \n"
                "**External Requests:** 0  \n"
                "**Mapping:** SESSION ONLY  \n"
                "**Supported:** TXT · PY · JSON"
            )

with st.container(
    horizontal=True,
    vertical_alignment="center",
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
        key="detects_row",
    ):
        st.caption("DETECTS")
        st.badge("Email", color="gray")
        st.badge("IPv4", color="gray")
        st.badge("Passwords", color="gray")
        st.badge("API Keys", color="gray")
        st.badge("Tokens", color="gray")

    uploaded_file = st.file_uploader(
        "Upload a file (optional)",
        type=["txt", "py", "json"],
        key="uploaded_file",
        on_change=clear_active_file,
        max_upload_size=2,
    )
    st.caption(
        "Files are processed locally in memory and are not uploaded to an "
        "external service."
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
                st.session_state["source_text"] = uploaded_text
                st.session_state["active_input_name"] = uploaded_file.name

    if st.session_state["active_input_name"]:
        st.success(
            f'Active input: uploaded file "{st.session_state["active_input_name"]}"'
        )

    st.caption("OR PASTE CONTENT")
    source_text = st.text_area(
        "Source code, logs, credentials, or text",
        height=260,
        placeholder="Paste sensitive content here...",
        key="source_text",
        on_change=clear_active_file,
    )

with st.container(horizontal=True, key="primary_action"):
    sanitize_clicked = st.button(
        "Sanitize & Protect",
        type="primary",
        key="primary_sanitize",
        width="content",
    )

if sanitize_clicked:
    if not source_text.strip():
        st.warning("Enter some text to sanitize.")
    else:
        with st.spinner("Scanning locally for sensitive data...", show_time=False):
            sanitized_text, detection_counts, placeholder_mapping = sanitize_text(
                source_text
            )
        st.session_state["placeholder_mapping"] = placeholder_mapping
        st.session_state["sanitized_output"] = sanitized_text
        st.session_state["sanitized_filename"] = sanitized_filename_for(
            st.session_state["active_input_name"]
        )
        total_entities = sum(detection_counts.values())
        categories_detected = sum(
            count > 0 for count in detection_counts.values()
        )

        with st.container(border=True, key="protection_status"):
            st.success(
                f"{total_entities} sensitive entities neutralized · "
                "0 external requests",
                title="✓ Content Protected",
            )
            with st.container(horizontal=True, key="security_metrics"):
                st.metric(
                    "Categories Detected", categories_detected, border=True
                )
                st.metric("Local Processing", "100%", border=True)
                st.metric("External Requests", 0, border=True)

        st.subheader("2. Detection Summary")
        st.caption("DETAILED DETECTIONS")
        email_column, ipv4_column, password_column, api_key_column = st.columns(4)
        email_column.metric("Email", detection_counts["Email"])
        ipv4_column.metric("IPv4", detection_counts["IPv4"])
        password_column.metric(
            "Password", detection_counts["Password"]
        )
        api_key_column.metric(
            "API Key / Token",
            detection_counts["API Key / Token"],
        )

        if total_entities == 0:
            st.info("No sensitive information detected.")

if st.session_state["sanitized_output"] is not None:
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
            st.download_button(
                "Download Sanitized File",
                data=st.session_state["sanitized_output"],
                file_name=st.session_state["sanitized_filename"],
                mime=mime_type_for(st.session_state["sanitized_filename"]),
                key="download_sanitized",
                on_click="ignore",
            )

with st.container(
    horizontal=True,
    vertical_alignment="center",
    key="restore_workflow",
):
    st.badge("Sanitized Prompt", color="blue")
    st.markdown("→")
    st.badge("External AI", color="gray")
    st.markdown("→")
    st.badge("Placeholder Response", color="blue")
    st.markdown("→")
    st.badge("Local Restore", color="green")

st.subheader("4. Restore AI Response")
with st.container(border=True, key="restore_section"):
    st.caption(
        "Paste the AI response containing DocuGuard placeholders to restore "
        "your original values locally."
    )
    st.caption(
        "🔒 Restoration uses only the temporary mapping stored in this session."
    )

    ai_response = st.text_area(
        "AI response",
        height=200,
        placeholder="Paste an AI response with DocuGuard placeholders here...",
    )

    if st.button("Restore Original Values"):
        current_mapping = st.session_state.get("placeholder_mapping", {})

        if not current_mapping:
            st.warning(
                "Sanitize some content first to create a restoration mapping."
            )
        elif not ai_response.strip():
            st.warning("Enter an AI response to restore.")
        else:
            restored_text = restore_text(ai_response, current_mapping)
            st.success("✓ Original values restored locally")
            st.subheader("Restored Response")
            st.code(restored_text, language=None)

with st.container(key="footer_note"):
    st.markdown("**DocuGuard · Local-first privacy for AI workflows**")
    st.caption("Built for Grevix AfterCode")
    st.caption(
        "No external AI or cloud API is contacted by DocuGuard."
    )
