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
- Infrastructure Monitor: CPU, memoria, disco, red, uptime del servidor local y servidores remotos.
- Mapa de ciberamenazas: visualizacion SOC demostrativa o fuente externa configurable.
- IOC Center: registro y exportacion CSV/JSON de IOCs.
- Threat Intelligence: reputacion VirusTotal con cache local.
- OWASP: guia y mapping de hallazgos.
- Reports: reportes HTML/JSON y evidencia.
- Settings: perfil, contrasena, region y VirusTotal.
- Settings: perfil, contrasena, region, VirusTotal y fuente externa del Threat Map.

Idioma:

- La interfaz inicia en espanol por defecto.
- Usa el selector del header para cambiar entre `Espanol` y `English`.
- La preferencia queda guardada en la sesion y en el usuario autenticado.

Reportes:

- En Reportes y Detalle de Escaneo usa `Ver reporte`, `Descargar HTML`, `Descargar JSON` o `Descargar PDF`.
- Los PDF ejecutivos se guardan en `reports/pdf/`.
- Si falta WeasyPrint, instala `pip install -e ".[pdf]"` y vuelve a intentar.
- Si WeasyPrint falla, VigiScan intenta generar un respaldo con ReportLab.

Threat Map:

- Abre `/threat-map`.
- Para usar una fuente externa, ve a Configuracion y activa `Activar mapa externo`.
- Si el proveedor bloquea iframe o no hay internet, VigiScan muestra una visualizacion demostrativa local.

Infrastructure remoto:

- En `/infrastructure`, registra servidores con metodo `Local`, `Agent/API` o `Manual`.
- Para Agent/API, el servidor remoto debe exponer JSON con campos como `cpu_percent`, `memory_percent`, `disk_percent`, `upload_rate`, `download_rate`, `active_processes` y `uptime`.
- Si no hay agente configurado, el estado queda como `Pendiente de agente`.
- En Uptime y Assets puedes asociar cada aplicacion o activo a un servidor.

Ejecucion en red:

```bash
flask --app vigiscan.web.app run --host=0.0.0.0 --port=5000
```

Actualizar desde GitHub:

```bash
git pull origin main
pip install -e ".[pdf]"
python -m pytest
```
