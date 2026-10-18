# Historial de cambios

Todos los cambios relevantes de HeaderGuard se documentan aquí. El formato sigue la idea de [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto utiliza versionado semántico.

## [1.3.0] - 2026-10-18

### Añadido

- `HeaderGuard-Lite.html`, una edición autónoma que funciona con doble clic, sin instalación ni conexión.
- Analizador JavaScript con paridad automatizada frente al motor Python.
- Historial privado, generador de configuración y exportaciones JSON/HTML en la edición Lite.
- Capturas y pruebas reales de escritorio y móvil mediante `file://`.
- Guía comparativa para elegir, instalar y usar cada edición.

### Mejorado

- Docker se presenta como alternativa opcional; la instalación directa con Python queda explicada paso a paso.
- GitHub Actions comprueba que el HTML autónomo esté actualizado y ejecuta ambas interfaces con Chromium.
- Estructura pública de documentación simplificada y orientada a usuarios del proyecto.

### Seguridad

- Política CSP con hashes SHA-256 y `connect-src 'none'` en la edición Lite.
- Ningún valor de cookie se muestra, conserva o exporta.
- La edición Lite no incorpora escaneo remoto ni dependencias externas.

## [1.2.0] - 2026-10-18

### Añadido

- Análisis de atributos de cookies sin devolver ni almacenar sus valores.
- Generador de configuraciones para Nginx, Apache, FastAPI y Express.
- Informe HTML autónomo descargable.
- Enlaces educativos oficiales de MDN y OWASP en cada resultado.
- Banner propio de HeaderGuard para GitHub.
- Pruebas end-to-end con Chromium y capturas automáticas de escritorio y móvil.

### Seguridad

- `Set-Cookie` se elimina de las cabeceras devueltas por la API después de analizar sus atributos.

## [1.1.0] - 2026-10-18

### Añadido

- Validación de calidad para CSP, HSTS y otras cabeceras, además de comprobar su presencia.
- Estados diferenciados: seguro, advertencia y ausente.
- Historial privado local y comparación con el análisis anterior.
- Exportación del informe en JSON, impresión/PDF, resumen y badge para GitHub.
- Tema claro y oscuro persistente.
- Ejemplo seguro precargable y avisos visuales.
- Guía de publicación en GitHub y plantillas para colaborar.

### Mejorado

- Diseño responsive con identidad visual abyssnx.
- Mensajes de error y prioridades del informe.
- Cobertura automatizada del analizador, API y defensas SSRF.

### Seguridad

- Validación por capas contra SSRF, redes no públicas y DNS rebinding.
- Redirecciones, puertos, tiempos, tamaño de entrada y frecuencia limitados.

## [1.0.0] - 2026-10-18

### Añadido

- Primera versión funcional con FastAPI.
- Análisis remoto y análisis de cabeceras pegadas.
- Puntuación de nueve cabeceras HTTP de seguridad.
- Tests, Docker, GitHub Actions, licencia MIT y política de seguridad.
