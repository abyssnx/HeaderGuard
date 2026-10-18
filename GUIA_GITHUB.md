# Mantenimiento de HeaderGuard en GitHub

El repositorio oficial es [abyssnx/HeaderGuard](https://github.com/abyssnx/HeaderGuard). Esta guía resume cómo revisar cambios, publicar versiones y mantener una presentación profesional.

## Información del repositorio

Descripción recomendada:

> Analizador visual de cabeceras HTTP de seguridad con edición HTML autónoma, FastAPI y protección SSRF.

Temas recomendados:

~~~text
cybersecurity http-security security-headers fastapi python ssrf web-security appsec
~~~

## Antes de subir cambios

Desde la raíz del proyecto:

~~~bash
python scripts/build_standalone.py --check
ruff check .
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
~~~

Si has modificado la interfaz y tienes Playwright instalado, ejecuta también las pruebas de navegador:

~~~bash
python -m playwright install chromium
pytest tests/test_ui.py tests/test_lite_ui.py
~~~

Comprueba además:

- `git status` solo muestra archivos relacionados con el cambio.
- README, guías y ejemplos coinciden con el comportamiento actual.
- No hay secretos, entornos virtuales, caches ni informes locales.
- `CHANGELOG.md` recoge los cambios visibles para usuarios.

## Subir una mejora

~~~bash
git add README.md docs/ CHANGELOG.md
git commit -m "docs: mejora las guías de uso y API"
git push origin main
~~~

Para cambios de código, utiliza una rama y un pull request cuando quieras conservar una revisión separada.

## Publicar una versión

1. Actualiza la versión en `pyproject.toml`, `app/main.py`, `app/scanner.py`, `app/static/index.html` y la etiqueta OCI del `Dockerfile`.
2. Añade una sección fechada a `CHANGELOG.md`.
3. Regenera `HeaderGuard-Lite.html` si han cambiado sus fuentes o reglas.
4. Ejecuta toda la suite.
5. Crea y sube el commit.
6. Espera a que GitHub Actions finalice correctamente.
7. Crea una etiqueta, por ejemplo:

~~~bash
git tag -a v1.4.0 -m "HeaderGuard v1.4.0"
git push origin v1.4.0
~~~

8. En GitHub, abre **Releases → Draft a new release**.
9. Selecciona la etiqueta, resume los cambios y adjunta el ZIP si deseas ofrecer una descarga directa.

## Preparar el ZIP

El ZIP debe contener directamente los archivos del proyecto, no una carpeta duplicada. Excluye:

- `.git/`
- `.venv/`
- Caches de Python, Ruff y pytest.
- Cobertura local.
- Borradores de publicaciones o imágenes externas al repositorio.

Después de crearlo, descomprímelo en una carpeta temporal y comprueba que Lite abre con doble clic y que README aparece en la raíz.

## Comprobaciones en GitHub

Después de cada publicación:

- La acción **CI** termina en verde.
- El banner y la captura del README cargan correctamente.
- Los enlaces internos no devuelven 404.
- GitHub detecta la licencia MIT.
- Las plantillas de incidencias y pull requests están disponibles.
- Dependabot puede revisar las acciones configuradas.
- La pestaña **Security** permite crear avisos privados.

## Protección recomendada de main

En **Settings → Branches** puedes exigir:

- Que CI finalice correctamente.
- Que la rama esté actualizada antes de integrar.
- Que no se fuerce el historial.
- Revisión por pull request cuando colaboren más personas.

Para un proyecto personal también es válido trabajar directamente en `main`, siempre que las comprobaciones pasen antes y después del push.

## Presentar el proyecto

Una demostración corta puede seguir este orden:

1. Abrir `HeaderGuard-Lite.html` con doble clic.
2. Cargar el ejemplo y explicar la puntuación.
3. Mostrar una prioridad y su recomendación.
4. Arrancar la edición completa.
5. Escanear una URL pública autorizada.
6. Enseñar la documentación en `/api/docs`.
7. Explicar brevemente la protección SSRF y las pruebas automatizadas.

Consulta [README.md](README.md) para la presentación principal y [docs/GUIA_USO.md](docs/GUIA_USO.md) para instrucciones completas.
