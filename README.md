# Phishing Shield (HV-0077-Deadlock)

A browser extension + backend service that detects phishing and smishing (SMS phishing) attempts in real time.

## Overview
- **Chrome Extension** — runs heuristic checks on every page (URL patterns, typosquatting, mismatched login forms, hidden text, obfuscated scripts), escalates ambiguous cases to an AI model, and blocks high-risk pages with a warning overlay.
- **Backend (FastAPI)** — a standalone service for domain-permutation scanning and SMS/screenshot (OCR) smishing analysis.

## Architecture