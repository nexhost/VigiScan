# VigiScan

VigiScan is a Python 3.12 command line security scanner scaffold focused on
small, composable modules and local report generation.

The current version includes an HTTP scanner boundary, security header checks,
technology detection, common path exposure checks, local CVE lookup, and report
generation.

## Requirements

- Python 3.12 or newer

## Installation

Install the project in editable mode during development:

```bash
python -m pip install -e .
```

## Usage

After installation, the command line entry point is available as:

```bash
vigiscan --url https://example.com --report html
```

The command shows a professional Rich banner, runs the scanner modules, and
saves the requested report format.

CLI options:

- `--timeout`: HTTP timeout in seconds.
- `--report`: output format, one of `html`, `json`, `txt`, or `all`.
- `--output`: output directory for generated reports.
- `--verbose`: show detailed execution progress.

The scanner provides a normalized structure with:

- `ok`: whether URL validation and the HTTP request succeeded.
- `target`: normalized URL metadata.
- `request`: outbound request settings such as method and timeout.
- `response`: HTTP response metadata and a bounded body sample.
- `error`: normalized validation or request error details.

## Modules

The HTTP security headers module covers:

- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`

The technology detection module can identify common technologies from headers,
cookies, meta tags, and HTML:

- Apache
- Nginx
- PHP
- WordPress
- Laravel
- OpenSSL

The directories module checks a small local wordlist of common sensitive paths:

- `.env`
- `.git/`
- `backup.zip`
- `config.php`
- `phpinfo.php`
- `admin/`
- `login/`
- `backup/`

The CVE checker performs local lookups from `vigiscan/data/cve_local.json` and
relates product, version, CVE, severity, and description. The bundled examples
include Apache `2.4.49`, WordPress, and OpenSSL.

The report module generates TXT, JSON, and HTML outputs in `reports/`. Reports
include an executive summary and a normalized risk score from `0` to `100`.

## Project Layout

```text
.
|-- pyproject.toml
|-- README.md
|-- LICENSE
|-- reports/
|-- vigiscan/
|   |-- __init__.py
|   |-- cli.py
|   |-- report.py
|   |-- scanner.py
|   |-- data/
|   `-- modules/
`-- tests/
```

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```
