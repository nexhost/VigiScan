# Desarrollo

Entorno recomendado:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest
ruff check .
```

Estructura:

- `scanner.py`: frontera HTTP defensiva.
- `modules/`: modulos historicos usados por CLI.
- `vigiscan/modules/`: modulos web/avanzados.
- `vigiscan/web/`: Flask, modelos, formularios, rutas y templates.
- `report.py`: render TXT/JSON/HTML.

Mantener cambios compatibles con `vigiscan` y `vigiscan-web`.
