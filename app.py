import re

import streamlit as st


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
    (?P<name>
        \b(?:
            (?:[A-Za-z][A-Za-z0-9_]*_)?(?:password|passwd|pwd)
            |api[_-]key
            |secret_key
            |api_secret
            |auth_token
            |private_key
            |access_token
            |token
            |secret
        )\b
    )
    (?P<equals>[ \t]*=[ \t]*)
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
    """Replace supported sensitive values and return the text plus match counts."""
    counts = {
        "Email": 0,
        "IPv4": 0,
        "Password": 0,
        "API Key / Token": 0,
    }
    value_mappings = {
        "Email": {},
        "IPv4": {},
        "Password": {},
        "API Key / Token": {},
    }

    def placeholder_for(category, placeholder_name, value):
        """Return one stable placeholder for each unique sensitive value."""
        category_mapping = value_mappings[category]

        if value not in category_mapping:
            counts[category] += 1
            category_mapping[value] = (
                f"[{placeholder_name}_{counts[category]}]"
            )

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
        return (
            f'{variable_name}{match.group("equals")}'
            f"{quote}{placeholder}{quote}"
        )

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

    return sanitized, counts


st.set_page_config(page_title="DocuGuard", layout="wide")

st.title("DocuGuard")
st.subheader("Local Privacy Layer for AI Workflows")
st.info(
    "Processing happens locally. DocuGuard does not send your input to an "
    "external AI service."
)

source_text = st.text_area(
    "Source code, logs, credentials, or text",
    height=320,
    placeholder="Paste sensitive content here...",
)

if st.button("Sanitize", type="primary"):
    if not source_text.strip():
        st.warning("Enter some text to sanitize.")
    else:
        sanitized_text, detection_counts = sanitize_text(source_text)

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
