# Guía de uso

Esta guía explica cómo empezar con HeaderGuard, elegir una edición e interpretar el informe. Si solo quieres probarlo, comienza con **HeaderGuard Lite**.

## Elegir una edición

| Necesidad | Edición recomendada |
| --- | --- |
| Probar la herramienta sin instalar nada | Lite |
| Trabajar sin conexión | Lite |
| Analizar cabeceras copiadas | Lite o completa |
| Escanear una URL pública | Completa |
| Integrar el analizador mediante API | Completa |

Ambas ediciones utilizan las mismas nueve reglas y el mismo modelo de puntuación.

## HeaderGuard Lite

### Abrir la aplicación

1. Descarga `HeaderGuard-Lite.html` desde el repositorio.
2. Abre el archivo con doble clic.
3. Pulsa **Cargar ejemplo** para ver un análisis inmediato.

No necesita Python, Docker ni conexión a internet. El contenido pegado permanece en la memoria del navegador y no se envía a ningún servidor.

### Obtener las cabeceras de una web

Desde las herramientas de desarrollo del navegador:

1. Abre una web para la que tengas autorización y pulsa `F12`.
2. Entra en **Red** o **Network** y recarga la página.
3. Selecciona la petición principal, normalmente la primera de tipo `document`.
4. Busca **Response headers** o **Cabeceras de respuesta**.
5. Copia el bloque completo y pégalo en HeaderGuard.

También puedes obtenerlas desde una terminal:

```bash
curl -I https://example.com
```

### Analizar

1. Pega la línea de estado y las cabeceras.
2. Pulsa **Analizar ahora**.
3. Revisa la nota global, las prioridades y cada regla.
4. Utiliza la configuración recomendada como punto de partida, nunca como sustituto de una revisión de tu aplicación.

## HeaderGuard completo

### Instalación con Python

Necesitas Python 3.11 o posterior.

```bash
git clone https://github.com/abyssnx/HeaderGuard.git
cd HeaderGuard
python -m venv .venv
```

Activa el entorno virtual.

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux o macOS:

```bash
source .venv/bin/activate
```

Instala y arranca la aplicación:

```bash
python -m pip install -e .
uvicorn app.main:app --reload
```

Abre `http://127.0.0.1:8000`. La documentación interactiva de la API está disponible en `http://127.0.0.1:8000/api/docs`.

### Instalación con Docker

```bash
docker build -t headerguard .
docker run --rm -p 8000:8000 headerguard
```

### Escanear una URL pública

1. Selecciona **Escanear URL**.
2. Introduce una URL completa que empiece por `http://` o `https://`.
3. Pulsa **Analizar**.

El backend valida el destino y cada redirección. Solo permite los puertos 80 y 443 y bloquea hosts locales, redes privadas y direcciones no públicas.

### Analizar cabeceras pegadas

Selecciona **Pegar cabeceras** cuando no quieras que HeaderGuard contacte con el sitio o cuando analices un servicio interno. El límite de entrada es de 32 KiB.

## Interpretar el informe

- **Puntuación:** suma ponderada de las nueve reglas, de 0 a 100.
- **Nota:** representación orientativa de la puntuación, de A a F.
- **Correcta:** la cabecera existe y supera las comprobaciones básicas.
- **Mejorable:** existe, pero contiene una configuración débil o incompleta.
- **Ausente:** no se ha encontrado en la respuesta.
- **Prioridades:** hasta tres recomendaciones iniciales siguiendo el orden de evaluación de las reglas.

Una puntuación alta no demuestra que una aplicación sea segura. HeaderGuard revisa cabeceras, no vulnerabilidades de negocio, autenticación, autorización ni código del servidor.

## Cookies y privacidad

HeaderGuard comprueba los atributos `Secure`, `HttpOnly`, `SameSite` y los prefijos `__Host-` y `__Secure-`. Los valores de las cookies se eliminan antes de mostrar o exportar el resultado.

El historial local solo conserva fecha, puntuación, nota y contadores. Puedes borrarlo desde la interfaz o eliminando los datos locales del navegador.

## Exportar resultados

Después de analizar puedes generar:

- JSON para conservar datos estructurados.
- HTML autónomo para compartir el informe visual.
- Una vista preparada para imprimir o guardar como PDF.
- Un resumen de texto y un badge para GitHub.

Revisa siempre el informe antes de compartirlo, especialmente si las cabeceras proceden de un entorno privado.

## Problemas frecuentes

### Lite muestra una página en blanco

Descarga el archivo mediante **Download raw file** o desde una versión publicada. No guardes la vista previa HTML de GitHub.

### PowerShell bloquea la activación del entorno

Puedes ejecutar Python directamente desde el entorno:

```powershell
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### El puerto 8000 está ocupado

```bash
uvicorn app.main:app --reload --port 8080
```

### Una URL pública es rechazada

Comprueba que utiliza HTTP/HTTPS, que no incluye credenciales, que usa el puerto 80 o 443 y que resuelve únicamente a direcciones públicas. Si el sitio bloquea solicitudes automatizadas, copia sus cabeceras y utiliza el modo manual.

## Uso responsable

Escanea únicamente sistemas propios o para los que tengas autorización. HeaderGuard es una herramienta educativa y no sustituye una auditoría profesional.
