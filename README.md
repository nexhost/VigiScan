# VigiScan

VigiScan is a defensive web security monitoring and vulnerability assessment
platform for analysts. It combines a Python CLI, Flask dashboard, executive
reports, uptime monitoring, asset inventory, IOC tracking, VirusTotal
reputation, OWASP mapping, local CVE enrichment, passive API, edge protection and TLS checks,
dependency review, and masked secret detection.

VigiScan helps detect multiple classes of web risk, but no tool can guarantee
100% vulnerability coverage. Use it only on assets you own or are explicitly
authorized to assess.

## Requirements

- Python 3.12 or newer

## Installation

Install the project in editable mode during development:

```bash
python -m pip install -e .
```

Optional PDF support for executive reports:

```bash
python -m pip install -e ".[pdf]"
```

## Instalacion en Linux Ubuntu 24.04 / 26.04

1. Actualizar sistema:

```bash
sudo apt update && sudo apt upgrade -y
```

2. Instalar dependencias:

```bash
sudo apt install git python3 python3-pip python3-venv -y
```

3. Clonar repositorio:

```bash
git clone https://github.com/nexhost/VigiScan.git
cd VigiScan
```

4. Crear entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

5. Instalar VigiScan:

```bash
pip install -e .
```

6. Probar CLI:

```bash
vigiscan --url https://example.com --report html
```

7. Ejecutar dashboard:

```bash
vigiscan-web
```

8. Abrir dashboard:

```text
http://127.0.0.1:5000
```

9. Acceso por red:

```bash
VIGISCAN_WEB_HOST=0.0.0.0 VIGISCAN_WEB_PORT=5000 vigiscan-web
```

10. Credenciales por defecto:

- Usuario: `admin`
- Contrasena: `admin`

11. Cambiar contrasena desde `Settings`.

12. Actualizar VigiScan:

```bash
cd ~/VigiScan
git pull origin main
source .venv/bin/activate
pip install -e .
```

13. Ejecutar pruebas:

```bash
python -m pytest
```

14. Errores comunes:

- `externally-managed-environment`: usa un entorno virtual con `python3 -m venv .venv`.
- `vigiscan command not found`: activa `.venv` o reinstala con `pip install -e .`.
- Puerto `5000` ocupado: usa `VIGISCAN_WEB_PORT=5001 vigiscan-web`.
- SQLite bloqueada: cierra otros procesos del dashboard y reintenta.
- Error PDF / WeasyPrint: instala `pip install -e ".[pdf]"` dentro del entorno virtual. En Linux instala tambien dependencias del sistema si WeasyPrint lo solicita.
- `git pull` con cambios locales: revisa `git status`, guarda o commitea antes de actualizar.
- Permisos en Linux: evita `sudo pip`; usa `.venv`.

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

## Web Dashboard

Start the dashboard with:

```bash
vigiscan-web
```

The first run creates a local SQLite database at `instance/vigiscan.sqlite3`
and an initial administrator:

- Username: `admin`
- Password: `admin`

Override the initial account and server settings with environment variables:

- `VIGISCAN_ADMIN_USERNAME`
- `VIGISCAN_ADMIN_PASSWORD`
- `VIGISCAN_SECRET_KEY`
- `VIGISCAN_WEB_HOST`
- `VIGISCAN_WEB_PORT`
- `VIGISCAN_WEB_DEBUG`

Dashboard scans run the same VigiScan engine used by the CLI. Each scan stores
the target URL, score, risk level, timestamp, generated HTML report path, and
full normalized report data in SQLite.

The web UI starts in Spanish by default and includes a header language selector
for Spanish/English. Authenticated users keep their selected language in their
profile and session.

Reports can be downloaded as HTML, JSON and, when the optional PDF backend is
installed, as executive PDF files under `reports/pdf/`.
If WeasyPrint cannot render in the current system, VigiScan falls back to
ReportLab when the `.[pdf]` extra is installed.

Threat Map is available at `/threat-map`. It can embed a configured external
source from Settings, and it shows a clearly labeled local demonstration view
when the external source is disabled or unavailable.

Remote infrastructure monitoring is available at `/infrastructure`. Register
servers as `Local`, `Agent/API` or `Manual`, then associate uptime applications
and assets with the server that hosts them.

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

The CVE checker performs local lookups from `data/cve_local.json` and
relates product, version, CVE, severity, and description. The bundled examples
include Apache `2.4.49`, WordPress, and OpenSSL.

The report module generates TXT, JSON, and HTML outputs in `reports/`. Reports
include an executive summary and a normalized risk score from `0` to `100`.

Additional defensive modules include:

- IOC Center for manually tracked indicators of compromise.
- Regional settings for country, timezone, currency and organization context.
- VirusTotal integration with encrypted key storage and local cache.
- TLS analyzer for certificate health and HTTP-to-HTTPS redirect checks.
- Edge protection detection using passive headers/cookies.
- API security checks for exposed Swagger/OpenAPI/GraphQL, CORS and methods.
- Secret scanner with masked evidence.
- Dependency scanner for local manifests.

## Roadmap de Integraciones

Future defensive integrations prepared for planning include Wazuh, OpenCTI,
MISP, Shodan, AbuseIPDB, HaveIBeenPwned, SecurityTrails, Censys, Nuclei
templates, Semgrep, Gitleaks, Trivy, Grype and OSV.

See `docs/` for complete Linux, usage, dashboard, development and security
guides.

## Project Layout

```text
vigiscan/
|-- cli.py
|-- scanner.py
|-- report.py
|-- modules/
|-- vigiscan/
|   |-- __init__.py
|   `-- web/
|       |-- app.py
|       |-- models.py
|       |-- auth.py
|       |-- routes.py
|       |-- forms.py
|       |-- templates/
|       |   |-- base.html
|       |   |-- login.html
|       |   |-- dashboard.html
|       |   |-- scan_new.html
|       |   |-- scan_detail.html
|       |   `-- reports.html
|       `-- static/
|           |-- css/
|           `-- js/
|-- data/
|-- reports/
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
