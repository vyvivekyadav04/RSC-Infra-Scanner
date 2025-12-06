# RSC Infra Scanner

`rsc_infra_scan.py` is a fast, asynchronous Python tool that **fingerprints domains for likely Next.js App Router / React Server Components (RSC) infrastructure**.

It does **not** exploit any vulnerabilities.  
It only performs **passive HTTP/HTML/header fingerprinting** to help you identify targets that might be in the affected technology family (e.g. for RSC‑related CVEs).

## Target Vulnerabilities

This scanner is designed to help identify infrastructure that MAY be vulnerable to:

- **CVE-2025-55182** — Critical Remote Code Execution (RCE) vulnerability in React Server Components due to unsafe deserialization. This vulnerability allows pre-authentication remote code execution.
- **CVE-2025-66478** — Initially assigned to Next.js but marked as a duplicate of CVE-2025-55182.

### Affected Versions

- **React**: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- **Next.js**: 15.x and 16.x using the App Router

> **Important**: This tool only identifies infrastructure that *appears* to use Next.js App Router / RSC technology. It does **not** verify if a specific CVE is exploitable or if the target is running a vulnerable version. Always verify vulnerability status through proper security testing and vendor advisories.

---

## Features

- Scans a list of domains concurrently using `aiohttp`.
- Detects heuristics for:
  - `window.__next_f` (Next.js App Router / RSC runtime)
  - `react-server-dom-webpack`
  - `id="__next"` container
  - `x-nextjs-*` response headers
  - `Content-Type: text/x-component`
- Assigns a **0–100 score** per domain.
- Prints a CSV‑like summary with:
  - A **green `[+]` mark** for “likely RSC / Next.js infra” (score ≥ 50).
  - A **red `[-]` mark** for “unlikely / not detected” or errors.
- Uses **HTTPS by default**, with HTTP fallback if there is an SSL issue.

> This tool is intended for **research and defensive security testing**. Do not use it on systems you are not authorized to test.

---

## Installation

1. Clone or download this repository.

2. Install Python dependencies:

   ```bash
   pip install aiohttp
   ```

3. Ensure you have Python 3.8+.

---

## Configuration

Create a `List.txt` file in the same directory as `rsc_infra_scan.py`.

- One domain or URL per line.
- `#` at the beginning of a line is treated as a comment.
- You can mix bare domains and full URLs.

Example `List.txt`:

```text
# Example targets
example.com
https://subdomain.example.org
nextjs-demo.vercel.app
```

---

## Usage

Run the scanner from the directory containing `rsc_infra_scan.py` and `List.txt`:

```bash
python rsc_infra_scan.py
```

The script will:

- Read `List.txt`.
- De-duplicate domains.
- Probe each target concurrently.
- Print a CSV‑like table to stdout.

---

## Output Format

Header:

```text
domain,status,is_rsc_like,score,signals_or_error
```

Example rows:

```text
example.com,[+],yes,75,HTML:(window|self)\.__next_f\s*=; HDR:x-nextjs-cache=HIT
legacy-site.org,[-],no,0,
bad-ssl.test,[-],ERROR,0,SSL: CERTIFICATE_VERIFY_FAILED
```

Where:

- `status`:
  - `[+]` (green in a terminal that supports ANSI) → **likely using Next.js App Router / RSC‑style infra**.
  - `[-]` (red) → no strong signals or an error.
- `is_rsc_like`:
  - `yes` when `score >= 50`.
  - `no` otherwise.
- `score`:
  - 0–100 heuristic score, based on HTML patterns and headers.
- `signals_or_error`:
  - Semi‑colon separated list of matched signals (e.g. `HTML:...`, `HDR:...`) or an error message.

---

## How Detection Works (High Level)

The scanner sends a single GET request per target (with HTTP fallback if HTTPS fails) and inspects:

1. **HTML body**
   - `window.__next_f` → strong Next.js App Router / RSC indicator.
   - `react-server-dom-webpack` → RSC library reference.
   - `id="__next"` → generic Next.js root container.

2. **Response headers**
   - `x-nextjs-cache`
   - `x-nextjs-matched-path`
   - `x-nextjs-page`
   - `x-nextjs-router-state-tree`
   - `Content-Type: text/x-component`

Each signal contributes to the overall score. A score ≥ 50 means the domain is "RSC‑infra‑like".

> Note: This is **not a vulnerability scanner**. It cannot tell you if a specific CVE (such as CVE-2025-55182 or CVE-2025-66478) is exploitable, only whether the stack looks like Next.js/RSC infrastructure that *might* be affected. Always verify actual vulnerability status through proper security testing and consult official vendor advisories.

---

## Legal & Ethical Use

- Only scan systems that you:
  - Own yourself, or
  - Have **explicit written permission** to test.
- Do not treat heuristic detection as proof of vulnerability; always follow coordinated disclosure and patch guidance from vendors.

---

## References

For more information about the vulnerabilities this tool helps identify:

- **CVE-2025-55182**: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- **CVE-2025-66478**: [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-66478) (marked as duplicate of CVE-2025-55182)
- React Security Advisory: Check the official React repository for security advisories
- Next.js Security Advisory: Check the official Next.js repository and [Vercel Community](https://community.vercel.com/t/security-advisory-for-cve-2025-55182-and-cve-2025-66478/29095) for updates

---

## Disclaimer

This project is provided for **educational and research purposes only**.

The author(s) are **not responsible** for any misuse or damage caused by this software.  
You are solely responsible for complying with all applicable laws and regulations when using this tool.
