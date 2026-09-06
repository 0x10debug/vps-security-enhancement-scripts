# vps-security-enhancement-scripts AGENTS.md

## Testing Convention (Iron Rule)

**Every full test cycle must produce a test report placed in the repo root, referenced from the README, and written in English.**

1. **Report location**: The test report file must be placed in the **repo root directory** (not in `dev-docs/`, `docs/`, or any subdirectory). Filename format: `TEST-REPORT-v<version>.md` (e.g., `TEST-REPORT-v4.0.0.md`).

2. **README reference**: `README.md` must reference the test report in a blockquote at the **very top** of the file, immediately after the title line. The reference must include:
   - Link to the test report file
   - Test count and environment summary
   - Pass rate

3. **Changelog tracking**: The README must include a changelog blockquote at the top tracking all bug fixes and updates discovered during testing. Each entry must list:
   - Affected script filename
   - Brief description of the fix (one line)

4. **Report language**: The test report, like all repository content, must be written in **English** (no-Chinese policy).

5. **Report standard**: The report must follow aviation-industrial-grade formatting:
   - Document ID (e.g., `TR-VPS-YYYY-MMDD-NNN`)
   - Executive summary with test results overview table
   - Test environment specification (hardware + software)
   - Detailed test results per test case (test ID, method, pass criteria, result)
   - Defect details (ID, severity, root cause, fix, verification, status)
   - Test coverage matrix
   - Sign-off section

6. **Report retention**: Old test reports are kept in the repo root for trend comparison. Do not delete previous reports when adding new ones.
