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

st.title("DocuGuard")
st.subheader("Local Privacy Layer for AI Workflows")
st.info(
    "Processing happens locally. DocuGuard does not send your input to an "
    "external AI service."
)

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

source_text = st.text_area(
    "Source code, logs, credentials, or text",
    height=320,
    placeholder="Paste sensitive content here...",
    key="source_text",
    on_change=clear_active_file,
)

sanitized_this_run = False
if st.button("Sanitize", type="primary"):
    if not source_text.strip():
        st.warning("Enter some text to sanitize.")
    else:
        sanitized_text, detection_counts, placeholder_mapping = sanitize_text(
            source_text
        )
        st.session_state["placeholder_mapping"] = placeholder_mapping
        st.session_state["sanitized_output"] = sanitized_text
        st.session_state["sanitized_filename"] = sanitized_filename_for(
            st.session_state["active_input_name"]
        )
        sanitized_this_run = True

        st.subheader("Detection counts")
        email_column, ipv4_column, password_column, api_key_column = st.columns(4)
        email_column.metric("Email", detection_counts["Email"])
        ipv4_column.metric("IPv4", detection_counts["IPv4"])
        password_column.metric("Password", detection_counts["Password"])
        api_key_column.metric(
            "API Key / Token", detection_counts["API Key / Token"]
        )

        if sum(detection_counts.values()) == 0:
            st.info("No sensitive information detected.")

        original_column, sanitized_column = st.columns(2)

        with original_column:
            st.subheader("Original")
            st.code(source_text, language=None)

        with sanitized_column:
            st.subheader("Sanitized")
            st.code(sanitized_text, language=None)

if st.session_state["sanitized_output"] is not None:
    if not sanitized_this_run:
        st.subheader("Sanitized")
        st.code(st.session_state["sanitized_output"], language=None)

    st.download_button(
        "Download Sanitized File",
        data=st.session_state["sanitized_output"],
        file_name=st.session_state["sanitized_filename"],
        mime=mime_type_for(st.session_state["sanitized_filename"]),
        on_click="ignore",
    )

st.divider()
st.subheader("Restore AI Response")
st.caption(
    "Paste an AI response containing DocuGuard placeholders to restore the "
    "original values locally."
)
st.caption("Restoration happens locally using the current session mapping.")

ai_response = st.text_area(
    "AI response",
    height=200,
    placeholder="Paste an AI response with DocuGuard placeholders here...",
)

if st.button("Restore Original Values"):
    current_mapping = st.session_state.get("placeholder_mapping", {})

    if not current_mapping:
        st.warning("Sanitize some content first to create a restoration mapping.")
    elif not ai_response.strip():
        st.warning("Enter an AI response to restore.")
    else:
        restored_text = restore_text(ai_response, current_mapping)
        st.subheader("Restored Response")
        st.code(restored_text, language=None)
