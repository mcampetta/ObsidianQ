# ObsidianQ Secure Delivery QA Checklist

Date: __________  
Tester: __________  
Build/Commit: __________

## Legend
- `[ ]` Not Run
- `[x]` Pass
- `[!]` Fail

---

## A) Create Package (ZIP)

| ID | Test | Result | Notes |
|---|---|---|---|
| A1 | Add single file + password/confirm + Create Package | [ ] | |
| A2 | Verify package path auto-populates after success | [ ] | |
| A3 | Output exists as `*_SecureDelivery.zip` | [ ] | |
| A4 | Add folder with nested files + create | [ ] | |
| A5 | Enable **Compress files before packaging** + create | [ ] | |
| A6 | Toggle **Include simple extraction instructions** and create | [ ] | |
| A7 | Overwrite behavior when output already exists | [ ] | |

Expected:
- No crashes or hangs.
- Success status/log messages are clear.
- Output path preview is correct.

---

## B) Inspect / Verify

| ID | Test | Result | Notes |
|---|---|---|---|
| B1 | Inspect valid package | [ ] | |
| B2 | Verify valid package | [ ] | |
| B3 | Tamper package and verify fails | [ ] | |
| B4 | Verify error message is actionable | [ ] | |

Expected:
- Valid package verifies.
- Tampered package fails with clear reason.

---

## C) Extract

| ID | Test | Result | Notes |
|---|---|---|---|
| C1 | Extract valid package with correct password | [ ] | |
| C2 | Confirm extracted file tree matches source | [ ] | |
| C3 | Extract with wrong password fails cleanly | [ ] | |
| C4 | Extract to invalid/non-writable location shows error | [ ] | |
| C5 | Extract path traversal safety (no unsafe paths written) | [ ] | |

Expected:
- Correct password extracts.
- Wrong password fails gracefully.
- No unsafe extraction behavior.

---

## D) Validation / Error Handling

| ID | Test | Result | Notes |
|---|---|---|---|
| D1 | Create with no sources blocked/fails cleanly | [ ] | |
| D2 | Password mismatch blocked/fails cleanly | [ ] | |
| D3 | Short password (<10 chars) blocked/fails cleanly | [ ] | |
| D4 | Invalid output folder handled cleanly | [ ] | |
| D5 | Inspect/Verify/Extract with missing package path handled cleanly | [ ] | |

Expected:
- Clear messages.
- No unhandled exceptions.

---

## E) Legacy Regression Checks

| ID | Test | Result | Notes |
|---|---|---|---|
| E1 | File tab password mode encrypt/decrypt | [ ] | |
| E2 | File tab Secure Contacts mode encrypt/decrypt | [ ] | |
| E3 | Text tab password mode encrypt/decrypt | [ ] | |
| E4 | Text tab Secure Contacts mode encrypt/decrypt | [ ] | |
| E5 | Vault create/add/extract/list basic path | [ ] | |
| E6 | Exchange send/receive and inspect metadata parsing | [ ] | |

Expected:
- Existing workflows unaffected by Secure Delivery changes.

---

## F) UI Polish Findings

| Area | Check | Result | Notes |
|---|---|---|---|
| Layout | No clipping at default window size | [ ] | |
| Layout | Controls align cleanly | [ ] | |
| Controls | Tab order and keyboard flow sensible | [ ] | |
| Labels | Wording is non-technical and clear | [ ] | |
| Feedback | Status/log/progress are understandable | [ ] | |
| Theme | Colors/readability match app style | [ ] | |

---

## G) JSON/CLI Integration Sanity

| ID | Test | Result | Notes |
|---|---|---|---|
| G1 | `delivery create --json` returns valid JSON envelope | [ ] | |
| G2 | `delivery inspect --json` returns expected fields | [ ] | |
| G3 | `delivery verify --json` returns expected fields | [ ] | |
| G4 | `delivery extract --json` returns expected fields | [ ] | |
| G5 | Non-JSON legacy output remains intact for existing GUI paths | [ ] | |

---

## Summary

- Total Passed: ______
- Total Failed: ______
- Blockers: __________________________________________
- Recommended Fix Order:
  1. __________________________________________
  2. __________________________________________
  3. __________________________________________

