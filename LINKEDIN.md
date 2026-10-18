# Borrador para LinkedIn

🔐 Nuevo proyecto: HeaderGuard — HTTP Security Headers

Después de crear una herramienta para generar y entender comandos de Nmap, quería seguir construyendo proyectos pequeños con utilidad real para aprender ciberseguridad defensiva.

HeaderGuard analiza las cabeceras HTTP de seguridad de una web y convierte el resultado en una puntuación clara, con explicaciones y recomendaciones prácticas.

¿Qué incluye?

✅ Escaneo de URLs públicas y análisis de cabeceras pegadas
✅ Comprobación de CSP, HSTS, X-Frame-Options, Permissions-Policy y más
✅ Interfaz responsive y accesible
✅ Backend con FastAPI
✅ Protección SSRF: bloqueo de redes privadas, puertos restringidos, DNS validado y conexiones fijadas a la IP comprobada
✅ Tests y CI con GitHub Actions

Lo que más me ha servido de este proyecto no ha sido solo evaluar cabeceras: también he aprendido que una función aparentemente sencilla como “consultar una URL” necesita un modelo de amenazas serio cuando se ejecuta desde un servidor.

El repositorio está disponible aquí: https://github.com/abyssnx/HeaderGuard

Me encantará recibir feedback o ideas para la siguiente versión.

#CyberSecurity #AppSec #Python #FastAPI #OpenSource #WebSecurity #LearningInPublic
