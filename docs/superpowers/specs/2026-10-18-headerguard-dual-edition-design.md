# Diseño de HeaderGuard 1.3: edición Lite y edición completa

Fecha: 2026-10-18

## Objetivo

Ofrecer dos formas claras de utilizar HeaderGuard:

1. **HeaderGuard Lite**, un único archivo HTML que se abre con doble clic, funciona sin instalación y analiza cabeceras pegadas manualmente.
2. **HeaderGuard Completo**, la aplicación FastAPI actual, que conserva el análisis manual y añade el escaneo remoto protegido frente a SSRF.

El éxito consiste en que una persona sin conocimientos de Python o Docker pueda descargar el repositorio, abrir `HeaderGuard-Lite.html` y obtener un informe útil sin conexión. La edición completa no debe perder ninguna función existente.

## Alcance

### Edición Lite

La edición Lite incluirá:

- El mismo lenguaje visual profesional de HeaderGuard y la marca abyssnx.
- Análisis local de las nueve cabeceras de seguridad actuales.
- Detección de configuraciones débiles y cálculo de puntuación.
- Análisis de atributos de cookies sin mostrar, exportar ni guardar sus valores.
- Explicaciones, prioridades y enlaces educativos de MDN y OWASP.
- Generador de configuración para Nginx, Apache, FastAPI y Express.
- Historial local limitado a puntuaciones y contadores.
- Tema claro y oscuro.
- Exportación JSON, HTML, resumen y badge.
- Ejemplo seguro precargable.

No incluirá:

- Escaneo de URLs.
- Backend, servidor local, Docker o dependencias externas.
- Peticiones automáticas a servicios de terceros.
- Funciones que necesiten saltarse CORS mediante un proxy público.

### Edición completa

La edición completa conservará FastAPI, el escaneo remoto protegido frente a SSRF, el modo de cabeceras pegadas y todas las funciones de la versión 1.2. Docker continuará siendo opcional: también podrá ejecutarse directamente con Python.

## Arquitectura elegida

El repositorio tendrá un artefacto visible en la raíz:

```text
HeaderGuard-Lite.html
```

Este archivo contendrá HTML, CSS, JavaScript, iconos y reglas de análisis. No cargará fuentes, scripts, estilos ni imágenes remotas.

Para evitar mantener manualmente un archivo monolítico difícil de revisar, su código fuente se dividirá así:

```text
standalone/
├── lite.template.html
├── lite.css
└── lite.js
scripts/
└── build_standalone.py
```

`scripts/build_standalone.py` importará las reglas canónicas desde `app.analyzer.RULES`, las serializará de forma segura, insertará CSS y JavaScript en la plantilla y producirá `HeaderGuard-Lite.html`. El archivo final sí será autónomo; los archivos separados existen únicamente para facilitar mantenimiento y pruebas.

La compilación usará solo la biblioteca estándar de Python. No añadirá dependencias de producción.

## Flujo de usuario de la edición Lite

1. La persona abre `HeaderGuard-Lite.html` con doble clic.
2. Una etiqueta visible indica “Edición Lite · análisis local”.
3. Pega cabeceras o carga el ejemplo.
4. El navegador analiza el texto sin enviarlo a ningún servidor.
5. Se muestran puntuación, prioridades, cabeceras y cookies.
6. Puede generar una configuración o exportar el informe.
7. Un bloque discreto explica que el escaneo por URL está disponible en la edición completa.

No aparecerá una pestaña de URL desactivada. La interfaz mostrará únicamente acciones que funcionan, evitando confusión.

## Datos y privacidad

- Todo el análisis Lite ocurre en memoria dentro del navegador.
- El bloque de cabeceras pegado no se persiste.
- Los valores de `Set-Cookie` se descartan después de analizar sus atributos.
- `localStorage` guarda como máximo seis registros con fecha, puntuación, nota y contadores; nunca cabeceras o cookies.
- Los informes exportados contienen nombres y atributos de cookies, pero no valores.
- La edición Lite no ejecuta `fetch`, `XMLHttpRequest`, WebSocket ni servicios de analítica.

## Seguridad del HTML autónomo

El generador calculará hashes SHA-256 del CSS y JavaScript insertados y añadirá una política CSP mediante `<meta>`:

- `default-src 'none'`
- `script-src` y `style-src` limitados a los hashes generados
- `img-src data:` para el icono incluido
- `connect-src 'none'`
- `base-uri 'none'`
- `form-action 'none'`

Los datos introducidos por la persona se mostrarán con `textContent`. Los informes HTML aplicarán escape explícito a todos los datos. No se utilizarán `innerHTML`, `eval`, funciones dinámicas ni controladores de eventos inline con contenido no confiable.

La edición Lite no intentará consultar URLs arbitrarias desde el navegador. Hacerlo sería poco fiable por CORS y no permitiría reproducir las garantías SSRF de la edición completa.

## Paridad del analizador

Las reglas, pesos, explicaciones, recomendaciones y referencias procederán de `app.analyzer.RULES`. El JavaScript Lite implementará las mismas comprobaciones pragmáticas de calidad que Python.

Un test de paridad ejecutará casos representativos en ambos motores y comparará:

- Puntuación y nota.
- Estados seguro, advertencia y ausente.
- Puntos obtenidos por regla.
- Prioridades principales.
- Resumen de cookies.

La compilación fallará si las reglas serializadas no coinciden con las reglas del backend.

## Presentación en GitHub

El README comenzará con dos rutas de uso:

| Opción | Para quién | Cómo empezar | Escaneo URL |
| --- | --- | --- | --- |
| Lite | Quien quiere probarlo inmediatamente | Abrir `HeaderGuard-Lite.html` | No |
| Completa | Quien necesita escanear sitios públicos | Python o Docker | Sí, con protección SSRF |

La guía de GitHub explicará que Docker no es obligatorio. El ZIP incluirá ambas ediciones. `LINKEDIN.txt` mencionará que existe una versión de un solo archivo.

## Pruebas

### Automatizadas

- Tests unitarios del parser y analizador Lite.
- Test de paridad entre JavaScript y Python.
- Test de compilación determinista del HTML.
- Comprobación de que el HTML final no referencia activos remotos.
- Playwright abrirá `HeaderGuard-Lite.html` mediante `file://`, sin servidor.
- El flujo de navegador cargará el ejemplo, analizará, cambiará de tema, generará configuración y descargará un informe.
- La prueba interceptará solicitudes para confirmar que la aplicación no intenta acceder a la red.
- Se comprobarán escritorio y móvil.

### Manuales

- Doble clic en Windows con la red desconectada.
- Revisión visual en tema claro y oscuro.
- Confirmación de que ningún valor de cookie aparece en pantalla, historial o exportaciones.

## Cambios de versión y entrega

- La versión pasará a `1.3.0` en FastAPI, paquete, interfaz, Docker y documentación.
- `CHANGELOG.md` documentará la edición Lite.
- GitHub Actions reconstruirá el HTML y fallará si el artefacto versionado está desactualizado.
- El ZIP final se regenerará después de eliminar entornos virtuales y cachés.

## Criterios de aceptación

- `HeaderGuard-Lite.html` funciona mediante doble clic sin Python, Docker, servidor o internet.
- El archivo no ofrece ni simula escaneo remoto.
- Las nueve reglas y el análisis de cookies mantienen paridad con la edición completa.
- No se filtran valores de cookies.
- No se realizan solicitudes automáticas de red.
- Las exportaciones JSON y HTML funcionan desde `file://`.
- El README permite escoger una edición sin leer documentación técnica extensa.
- Todas las pruebas existentes y nuevas terminan correctamente.

## Decisiones explícitas

- Se mantienen las dos ediciones; Lite no reemplaza la aplicación FastAPI.
- No se usará un proxy CORS público.
- No se incorporarán frameworks frontend ni un gestor de paquetes JavaScript.
- El archivo HTML generado se guardará en Git para que pueda descargarse directamente desde GitHub.
- Docker permanece disponible, pero se presentará como una opción avanzada, no como requisito.
