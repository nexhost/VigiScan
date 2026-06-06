# Uso

CLI:

```bash
vigiscan --url https://example.com --report html
vigiscan --url https://example.com --report all --output reports
```

Dashboard:

```bash
vigiscan-web
```

Instalar soporte PDF opcional:

```bash
pip install -e ".[pdf]"
```

Modulos principales:

- Nuevo Escaneo: ejecuta analisis defensivo HTTP/HTTPS.
- Assets: inventario de superficie de ataque.
- Uptime Monitor: disponibilidad, SSL, respuesta, contexto de aplicaciones y acciones de pausa, edicion, eliminacion y chequeo manual.
- Infrastructure Monitor: CPU, memoria, disco, red, uptime del servidor y procesos activos.
- IOC Center: registro y exportacion CSV/JSON de IOCs.
- Threat Intelligence: reputacion VirusTotal con cache local.
- OWASP: guia y mapping de hallazgos.
- Reports: reportes HTML/JSON y evidencia.
- Settings: perfil, contrasena, region y VirusTotal.

Idioma:

- La interfaz inicia en espanol por defecto.
- Usa el selector del header para cambiar entre `Espanol` y `English`.
- La preferencia queda guardada en la sesion y en el usuario autenticado.

Reportes:

- En Reportes y Detalle de Escaneo usa `Ver reporte`, `Descargar HTML`, `Descargar JSON` o `Descargar PDF`.
- Los PDF ejecutivos se guardan en `reports/pdf/`.
- Si falta WeasyPrint, instala `pip install -e ".[pdf]"` y vuelve a intentar.
