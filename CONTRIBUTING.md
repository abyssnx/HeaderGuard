# Cómo contribuir

Gracias por querer mejorar HeaderGuard. Las contribuciones pequeñas, claras y verificables son bienvenidas.

## Preparar el proyecto

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

Activa el entorno virtual y ejecuta:

```bash
ruff check .
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
```

## Flujo recomendado

1. Abre una incidencia explicando el problema o propuesta.
2. Crea una rama corta desde `main`.
3. Añade tests cuando cambies comportamiento.
4. Mantén los mensajes y explicaciones de la interfaz en español.
5. No rebajes las defensas SSRF ni añadas nuevas dependencias sin justificarlo.
6. Abre un pull request usando la plantilla incluida.

## Seguridad

No publiques vulnerabilidades explotables en una incidencia. Sigue las indicaciones de [SECURITY.md](SECURITY.md).

## Estilo

- Python 3.11 o posterior.
- Formato compatible con Ruff y líneas de hasta 100 caracteres.
- JavaScript sin dependencias de terceros salvo que exista una necesidad clara.
- Cambios accesibles, responsive y compatibles con teclado.

Al contribuir aceptas que tu aportación se distribuya bajo la licencia MIT del proyecto.
