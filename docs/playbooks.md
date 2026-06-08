# Incident Response Playbook Mapping

## account_bruteforce_triage

**Trigger:** Multiple failed login attempts for the same user.

**Recommended actions:**

1. Validate source IP, user, and authentication method.
2. Check for successful login after failures.
3. Confirm whether MFA challenge occurred.
4. Review user risk and recent impossible travel indicators.
5. Reset session and require password reset if compromise is suspected.
6. Open an incident ticket with evidence and timeline.

## endpoint_script_execution_triage

**Trigger:** Suspicious PowerShell execution.

**Recommended actions:**

1. Collect process command line, parent process, user, and host.
2. Check EDR telemetry for related file or network activity.
3. Isolate endpoint if malicious behavior is confirmed.
4. Preserve relevant logs for investigation.
5. Hunt for the same command line or hash across endpoints.
6. Document MITRE ATT&CK mapping and containment actions.

## Design principle

The automation in this project recommends safe response steps. It does not execute destructive containment actions automatically.
