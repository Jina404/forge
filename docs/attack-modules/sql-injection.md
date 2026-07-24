# SQL Injection Module

## Purpose

Detect exploitable SQL injection behavior.

## Detection methods

- Error based
- Boolean based
- Time based

## Example finding

- Severity: Critical
- Endpoint: /api/user?id=
- Evidence: payload-induced delay and response difference
- Impact: database exposure risk
- Fix: parameterized queries
