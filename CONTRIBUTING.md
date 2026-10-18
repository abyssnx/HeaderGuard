# Cómo contribuir

Gracias por querer mejorar HeaderGuard. Se agradecen cambios pequeños, claros y verificables.

## Preparar el entorno

Necesitas Python 3.11 o posterior.

~~~bash
git clone https://github.com/abyssnx/HeaderGuard.git
cd HeaderGuard
python -m venv .venv
~~~

Activa el entorno.

Windows PowerShell:

~~~powershell
.venv\Scripts\Activate.ps1
~~~

Linux o macOS:

~~~bash
source .venv/bin/activate
~~~

Instala las dependencias:

~~~bash
python -m pip install -e ".[dev,ui]"
python -m playwright install chromium
~~~

## Comprobar cambios

~~~bash
python scripts/build_standalone.py --check
ruff check .
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
~~~

Si modificas `standalone/`, regenera la edición Lite:

~~~bash
python scripts/build_standalone.py
~~~

Incluye el archivo generado en el mismo cambio.

## Flujo recomendado

1. Abre una incidencia para problemas o propuestas importantes.
2. Crea una rama corta desde `main`.
3. Mantén cada pull request centrado en un objetivo.
4. Añade pruebas cuando cambies comportamiento.
5. Actualiza README o las guías si cambia el uso público.
6. Ejecuta todas las comprobaciones antes de enviar el pull request.

## Criterios del proyecto

- Interfaz y explicaciones orientadas a personas hispanohablantes.
- Python compatible con Ruff, líneas de hasta 100 caracteres.
- JavaScript sin dependencias de terceros salvo necesidad justificada.
- Cambios accesibles, responsive y utilizables con teclado.
- No rebajar las defensas SSRF ni sus pruebas.
- No mostrar, registrar ni exportar valores de cookies.
- No añadir dependencias sin explicar su beneficio y coste.

## Cambios de documentación

Comprueba que:

- Los comandos pueden copiarse sin modificaciones inesperadas.
- Los ejemplos no incluyen dominios, tokens o datos privados.
- Los enlaces internos utilizan rutas relativas.
- Las afirmaciones de seguridad coinciden con el código.
- La versión mostrada coincide con `pyproject.toml`.

## Seguridad

No publiques vulnerabilidades explotables en una incidencia. Sigue [SECURITY.md](SECURITY.md).

Al contribuir aceptas que tu aportación se distribuya bajo la licencia MIT del proyecto.
