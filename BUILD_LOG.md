# DocuGuard Build Log

This log records the major AI-assisted development decisions behind DocuGuard. AI tools provided recommendations, implementation support, and independent review; the participant made the final decisions and remained responsible for testing and the resulting application.

## Decision: Define a focused MVP scope

**Problem:** The project needed a working privacy tool within hackathon time constraints without introducing a large dependency or deployment burden.

**AI recommendation:** Start with Streamlit, Python, and regular expressions. Focus on high-value detection for emails, IPv4 addresses, passwords, and API keys, tokens, and secrets.

**My decision:** I selected a Streamlit and Python regex MVP with those four detection categories.

**Reason:** This scope was understandable, testable, and achievable while still demonstrating an end-to-end privacy workflow.

**Rejected alternatives:** Microsoft Presidio and spaCy were deliberately deferred because they would add setup, model, and integration complexity before the core workflow was proven.

## Decision: Use stable placeholders for repeated values

**Problem:** Numbering every occurrence independently caused the same sensitive value to receive different placeholders, weakening referential consistency.

**AI recommendation:** Keep a per-sanitization value-to-placeholder dictionary and reuse the assigned placeholder when the same value appears again.

**My decision:** I moved to stable placeholders for each unique value within one sanitize operation.

**Reason:** Consistent placeholders preserve relationships in code and text and make later restoration reliable.

**Rejected alternatives:** Independent occurrence numbering was rejected because repeated values such as an email address or server IP should remain identifiable as the same entity.

## Decision: Harden IPv4 and credential detection

**Problem:** Review identified missed IPv4 addresses before sentence punctuation, partial-match risks, invalid addresses, limited credential names, empty-value matches, and quoted credential edge cases.

**AI recommendation:** Refine the existing regex boundaries, validate IPv4 octets in the replacement callback, broaden recognized compound credential names, reject empty quoted values, and support escaped characters inside quoted credentials.

**My decision:** I accepted targeted regex and callback hardening without introducing a parser.

**Reason:** The changes fixed concrete correctness and safety issues while keeping the MVP readable.

**Rejected alternatives:** A complex parser and broad high-entropy secret scanner were rejected as unnecessary and risky for the current scope. Triple-quoted and multiline credentials remain a documented limitation.

## Decision: Add reversible session-only mapping

**Problem:** Permanent redaction prevented users from restoring sensitive values in an AI response containing placeholders.

**AI recommendation:** Return a placeholder mapping from sanitization, keep it in Streamlit session state, and restore only exact placeholders found in the current mapping.

**My decision:** I added local response restoration backed by the most recent session mapping.

**Reason:** Reversibility became the core differentiator while retaining local control of sensitive values.

**Rejected alternatives:** Disk persistence, a restoration database, an encryption system, and a UI exposing the complete mapping were rejected. Sensitive mappings remain session-only.

## Decision: Support local text-file input

**Problem:** Manual paste alone was inconvenient for source files, logs, and configuration documents.

**AI recommendation:** Accept only `.txt`, `.py`, and `.json`, decode UTF-8 with BOM support, process raw text in memory, and enforce a small file limit.

**My decision:** I added in-memory text upload for those three extensions with a 2 MB maximum.

**Reason:** This covered common demo inputs without adding file parsing or execution risks.

**Rejected alternatives:** PDF, DOCX, ZIP, binary formats, cloud storage, and executing uploaded Python were rejected. Python and JSON uploads are treated only as text.

## Decision: Fix JSON credential sanitization

**Problem:** Advertising `.json` upload support was unsafe while JSON-style credential fields such as `"api_key": "value"` could remain exposed.

**AI recommendation:** Extend the existing assignment pattern to preserve quoted keys, whitespace, colon separators, and quote style while replacing only the sensitive value.

**My decision:** I added colon-separated quoted-key recognition to the existing detection path.

**Reason:** JSON credentials needed the same protection as Python/config assignments, and the output needed to remain valid JSON text.

**Rejected alternatives:** A `json.loads()` sanitization pipeline was rejected because it could alter formatting and was unnecessary for raw-text replacement.

## Decision: Download sanitized text only

**Problem:** Users needed a safe way to move the protected output into another workflow without copying it manually.

**AI recommendation:** Download only the sanitized string, preserve supported uploaded-file extensions, and use a safe default filename for manual input.

**My decision:** I added sanitized download output with appropriate `.txt`, `.py`, or `.json` naming.

**Reason:** The export contains the useful protected content while excluding the original values, placeholder mapping, counts, and session data.

**Rejected alternatives:** ZIP, PDF, DOCX, cloud export, and embedding metadata or mappings in the download were rejected.

## Decision: Retain Streamlit for productization

**Problem:** The functional MVP needed stronger visual hierarchy and clearer privacy storytelling for a hackathon demo.

**AI recommendation:** Productize the existing Streamlit experience with restrained inline styling, factual status cards, clear workflow steps, detection summaries, and an Original/Protected comparison.

**My decision:** I retained Streamlit and completed controlled visual-polish passes inside `app.py`.

**Reason:** A separate frontend would have increased implementation and regression risk without improving the core privacy workflow.

**Rejected alternatives:** React, a separate frontend service, animation-heavy effects, fake terminal visuals, and external design dependencies were rejected.

## Decision: Use a defined AI-assisted workflow

**Problem:** AI assistance needed clear roles, review boundaries, and participant accountability.

**AI recommendation:** Separate product strategy, implementation, and independent review instead of relying on one tool for every decision.

**My decision:** ChatGPT supported technical leadership and strategy, OpenAI Codex handled implementation work, and Google Antigravity / Gemini provided independent review. I manually tested changes and made the final decisions.

**Reason:** Separation of responsibilities improved review quality while keeping human ownership explicit.

**Rejected alternatives:** Fully autonomous development or submission was rejected. The participant remained responsible for scope, review, testing, Git history, and the final implementation.

## Decision: Qualify the local-first security claim

**Problem:** Describing all possible deployments as device-local would be inaccurate if the Streamlit app were later hosted remotely.

**AI recommendation:** Tie privacy claims to the current localhost execution model and state exactly where mappings and uploads are handled.

**My decision:** I describe DocuGuard as local-first in its current local Streamlit configuration and explicitly distinguish a future remote deployment.

**Reason:** Security documentation must remain factual: the current app makes no external AI/API calls, processes uploads in memory, and keeps mappings in session state, but a remotely hosted instance would process user content on that host.

**Rejected alternatives:** Absolute claims such as “data can never leave the device” were rejected because they would not remain true under every deployment model.
