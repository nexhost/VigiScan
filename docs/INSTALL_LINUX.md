# Instalacion Linux

Guia para Ubuntu 24.04 y 26.04.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git python3 python3-pip python3-venv -y
git clone https://github.com/nexhost/VigiScan.git
cd VigiScan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
vigiscan --url https://example.com --report html
vigiscan-web
```

Abre `http://127.0.0.1:5000`. Credenciales iniciales: `admin` / `admin`.

Para acceso por red:

```bash
VIGISCAN_WEB_HOST=0.0.0.0 VIGISCAN_WEB_PORT=5000 vigiscan-web
```

Actualizacion:

```bash
git pull origin main
source .venv/bin/activate
pip install -e .
python -m pytest
```

Solucion rapida:

- `externally-managed-environment`: usa `.venv`.
- comando no encontrado: activa el entorno virtual.
- puerto ocupado: cambia `VIGISCAN_WEB_PORT`.
- SQLite bloqueada: cierra procesos abiertos.
- permisos: evita instalar con `sudo pip`.
