![HeaderGuard by abyssnx](docs/assets/headerguard-banner.svg)

# HeaderGuard — HTTP Security Headers

HeaderGuard analiza cabeceras HTTP de seguridad y las convierte en un informe visual con puntuación, prioridades y recomendaciones comprensibles.

[![CI](https://github.com/abyssnx/HeaderGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/abyssnx/HeaderGuard/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.3.0-8b5cf6)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e)

<p align="center">
  <img src="docs/assets/headerguard-preview.png" alt="Informe visual de HeaderGuard" width="900">
</p>

## ¿Qué hace?

- Evalúa nueve cabeceras de seguridad y detecta configuraciones débiles.
- Asigna una puntuación de 0 a 100 y una nota de A a F.
- Explica qué protege cada cabecera y qué conviene corregir primero.
- Revisa atributos de cookies sin mostrar sus valores.
- Genera configuraciones orientativas para Nginx, Apache, FastAPI y Express.
- Exporta el resultado como JSON, HTML, impresión/PDF, resumen o badge.

> HeaderGuard es una herramienta educativa. Una buena puntuación no sustituye una auditoría de seguridad.

## Prueba rápida

### Lite: sin instalar nada

1. Descarga [HeaderGuard-Lite.html](HeaderGuard-Lite.html).
2. Ábrelo con doble clic.
3. Pulsa **Cargar ejemplo** y después **Analizar ahora**.

Funciona sin Python, Docker, servidor ni conexión a internet. El análisis se realiza localmente en el navegador.

### Completa: escaneo de URLs y API

Necesitas Python 3.11 o posterior:

~~~bash
git clone https://github.com/abyssnx/HeaderGuard.git
cd HeaderGuard
python -m venv .venv
~~~

Activa el entorno virtual.

Windows PowerShell:

~~~powershell
.venv\Scripts\Activate.ps1
~~~

Linux o macOS:

~~~bash
source .venv/bin/activate
~~~

Instala y arranca:

~~~bash
python -m pip install -e .
uvicorn app.main:app --reload
~~~

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000). La API interactiva está en [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs).

## Elegir una edición

| Edición | Mejor para | Instalación | Escaneo por URL |
| --- | --- | --- | --- |
| **Lite** | Probar, aprender y trabajar sin conexión | Ninguna | No |
| **Completa** | Analizar webs públicas o utilizar la API | Python o Docker | Sí, con protección SSRF |

Las dos ediciones comparten las mismas reglas, puntuación, recomendaciones, análisis de cookies y exportaciones.

Consulta la [guía de uso](docs/GUIA_USO.md) para ver instrucciones detalladas, ejemplos e interpretación de resultados.

## Usar Docker

Docker es opcional. Si ya lo tienes instalado:

~~~bash
docker build -t headerguard .
docker run --rm -p 8000:8000 headerguard
~~~

Después abre [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Cómo obtener cabeceras

Desde el navegador:

1. Abre una web para la que tengas autorización y pulsa **F12**.
2. Entra en **Red** o **Network** y recarga la página.
3. Selecciona la petición principal.
4. Copia sus **cabeceras de respuesta**.

Desde una terminal:

~~~bash
curl -I https://example.com
~~~

Puedes pegar el resultado en cualquiera de las dos ediciones.

## Escanear una URL

En la edición completa, selecciona **Escanear URL**, introduce una dirección pública que empiece por `http://` o `https://` y pulsa **Analizar**. HeaderGuard mostrará la URL final, el estado HTTP, la puntuación y las recomendaciones.

Si el destino es interno o no quieres realizar una conexión desde HeaderGuard, utiliza **Pegar cabeceras**.

## Modelo de puntuación

| Cabecera | Peso |
| --- | ---: |
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 20 |
| X-Content-Type-Options | 10 |
| X-Frame-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| Cross-Origin-Opener-Policy | 5 |
| Cross-Origin-Resource-Policy | 5 |
| Cross-Origin-Embedder-Policy | 5 |

Los estados posibles son **correcta**, **mejorable** y **ausente**. HeaderGuard aplica comprobaciones prácticas, pero no conoce todos los requisitos funcionales de tu aplicación.

## Seguridad del escaneo remoto

La edición completa trata cada URL como hostil:

1. Solo permite HTTP/HTTPS y los puertos 80 y 443.
2. Rechaza credenciales, hosts locales, redes privadas e IP no públicas.
3. Valida todos los resultados DNS y fija la conexión a una IP aprobada.
4. Mantiene la validación TLS del nombre solicitado.
5. Vuelve a validar cada redirección y limita tiempo, tamaño y frecuencia.

Los valores de **Set-Cookie** se eliminan antes de mostrar o exportar resultados. Encontrarás los límites técnicos en la [documentación de la API](docs/API.md) y el procedimiento de reporte en [SECURITY.md](SECURITY.md).

## Documentación

| Documento | Contenido |
| --- | --- |
| [Guía de uso](docs/GUIA_USO.md) | Instalación, primeros pasos, informes y errores frecuentes |
| [API](docs/API.md) | Endpoints, ejemplos, respuestas y límites |
| [Arquitectura](docs/ARQUITECTURA.md) | Componentes, flujo de datos y controles SSRF |
| [Contribuir](CONTRIBUTING.md) | Entorno de desarrollo y normas del proyecto |
| [Seguridad](SECURITY.md) | Reporte responsable de vulnerabilidades |
| [Historial](CHANGELOG.md) | Cambios por versión |
| [Mantenimiento en GitHub](GUIA_GITHUB.md) | Releases, comprobaciones y presentación del repositorio |

## Solución de problemas

La [guía de uso](docs/GUIA_USO.md#problemas-frecuentes) explica qué hacer si Lite muestra una página en blanco, PowerShell bloquea el entorno, el puerto está ocupado o una URL es rechazada.

## Desarrollo y pruebas

Instala las dependencias de desarrollo y navegador:

~~~bash
python -m pip install -e ".[dev,ui]"
python -m playwright install chromium
~~~

Ejecuta las comprobaciones:

~~~bash
python scripts/build_standalone.py --check
ruff check .
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
~~~

GitHub Actions verifica el backend, las defensas SSRF, la paridad entre Python y JavaScript, el HTML autónomo y los recorridos reales de ambas interfaces con Chromium.

## Estructura

~~~text
HeaderGuard/
├── HeaderGuard-Lite.html    # Edición autónoma lista para abrir
├── app/                     # API, escáner protegido e interfaz completa
├── standalone/              # Fuentes de la edición Lite
├── scripts/                 # Generador determinista del HTML
├── tests/                   # Tests unitarios, seguridad y navegador
├── docs/                    # Guías, arquitectura y capturas
├── .github/                 # CI, Dependabot y plantillas
├── Dockerfile
├── SECURITY.md
└── LICENSE
~~~

## Contribuir

Las contribuciones son bienvenidas. Lee [CONTRIBUTING.md](CONTRIBUTING.md), añade pruebas cuando cambies comportamiento y utiliza solo sistemas propios o autorizados.

## Licencia

HeaderGuard se distribuye bajo la licencia [MIT](LICENSE).

---

Creado por **abyssnx**.
