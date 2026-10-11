# Challenge Card 2 — Real-World Feedback

## Public Feedback

DocuGuard was shared publicly on LinkedIn as part of the GREVIX AfterCode
Real-World Feedback challenge.

Two users provided constructive feedback.

### Feedback 1 — Privacy Report

A user suggested adding a "Risk Score & Privacy Report" so users could better
understand the severity of detected sensitive information and what DocuGuard
protected before content was shared with an AI tool.

## What Changed

Based on this feedback, DocuGuard now includes an explainable Privacy Report.

The report displays:

- Risk Level: LOW / MEDIUM / HIGH
- Reason for the assigned risk level
- Total sensitive entities detected
- Detection counts by category
- Local Processing status
- External Request count

The risk level is deterministic:

- HIGH — Password or API Key / Token / Secret detected
- MEDIUM — Email or IPv4 detected without credentials
- LOW — No supported sensitive entities detected

The report uses DocuGuard's existing detection counts and does not expose
the original sensitive values.

### Feedback 2 — Custom Detection Rules

Another user suggested allowing organization-specific custom detection rules
for proprietary tokens, internal IDs, and other sensitive formats.

This was considered valuable but intentionally deferred because expanding
the detection engine during the hackathon would increase regression risk.

It remains a potential future enhancement.

## Evidence

- `linkedin-post.png` — Public LinkedIn project post
- `feedback-hemangshu.png` — Privacy Report feedback
- `feedback-aditya.png` — Custom detection rule feedback
- `privacy-report.png` — Implemented improvement