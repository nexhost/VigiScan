# Dashboard

El dashboard muestra:

- Security Posture Score.
- Attack Surface Overview.
- Vulnerabilidades por severidad.
- OWASP Top 10 Distribution.
- CVE Trends.
- Uptime Monitor.
- Threat Intelligence Summary.
- IOCs recientes.
- Activos criticos.
- SSL Health.
- WAF Coverage.
- Pais y zona horaria activa.
- Infrastructure Monitor con CPU, RAM, disco, red, uptime del servidor y procesos.

La configuracion regional controla como se muestran fechas y contexto de
organizacion. VirusTotal no consulta la API si no hay key configurada o si el
resultado esta en cache vigente.

Rutas principales:

- `/dashboard`
- `/scan/new`
- `/reports`
- `/uptime`
- `/infrastructure`
- `/assets`
- `/iocs`
- `/threat-intel/virustotal`
- `/owasp`
- `/settings`

APIs JSON protegidas por login:

- `/api/dashboard/summary`
- `/api/dashboard/charts`
- `/api/uptime/summary`
- `/api/uptime/history`
- `/api/infrastructure/metrics`
- `/api/infrastructure/history`
