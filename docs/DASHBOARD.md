# Dashboard

El dashboard inicia en espanol por defecto y muestra:

- Puntuacion de seguridad.
- Resumen de superficie de ataque.
- Vulnerabilidades por severidad.
- OWASP Top 10 Distribution.
- CVE Trends.
- Monitor de disponibilidad.
- Resumen de inteligencia de amenazas.
- IOCs recientes.
- Activos criticos.
- SSL Health.
- Cobertura de proteccion perimetral.
- Pais y zona horaria activa.
- Infrastructure Monitor con CPU, RAM, disco, red, uptime del servidor y procesos.
- Selector ES/EN en el header.

La configuracion regional controla como se muestran fechas y contexto de
organizacion. VirusTotal no consulta la API si no hay key configurada o si el
resultado esta en cache vigente.

Rutas principales:

- `/dashboard`
- `/scan/new`
- `/reports`
- `/uptime`
- `/infrastructure`
- `/threat-map`
- `/assets`
- `/iocs`
- `/threat-intel/virustotal`
- `/owasp`
- `/settings`
- `/settings/language`
- `/reports/<scan_id>/pdf`
- `/scans/<scan_id>/pdf`

APIs JSON protegidas por login:

- `/api/dashboard/summary`
- `/api/dashboard/charts`
- `/api/uptime/summary`
- `/api/uptime/history`
- `/api/infrastructure/metrics`
- `/api/infrastructure/history`

Reportes ejecutivos PDF:

- Requieren el extra opcional `pip install -e ".[pdf]"`.
- Si WeasyPrint falla, VigiScan intenta un PDF de respaldo con ReportLab.
- Incluyen logo VigiScan, creditos de Kendry Rosario, portada, resumen ejecutivo, graficos estaticos, CVE, OWASP, plan de remediacion y conclusion.
- Se guardan en `reports/pdf/`.

Threat Map:

- `/threat-map` muestra una visualizacion SOC de ciberamenazas.
- En Configuracion se puede activar una URL externa embebible.
- Si la fuente externa no carga, se muestra una visualizacion demostrativa local claramente identificada.

Infrastructure remoto:

- `/infrastructure` permite registrar servidores locales, Agent/API o manuales.
- Uptime y Assets pueden asociarse a un servidor.
- Si no hay agente configurado, el estado se muestra como `Pendiente de agente`.

Roadmap de Integraciones:

- Wazuh
- OpenCTI
- MISP
- Shodan
- AbuseIPDB
- HaveIBeenPwned
- SecurityTrails
- Censys
- Nuclei templates
- Semgrep
- Gitleaks
- Trivy
- Grype
- OSV
