# Aliaddo Caldas MCP

Servidor MCP Streamable HTTP de solo consulta, con la herramienta `consultar_facturas`.

## Render

- Build: `npm ci`
- Start: `npm start`
- Configura `ALIADDO_TOKEN`: token de Mis datos > Integracion de Aliaddo, ya en el formato Bearer que entrega Aliaddo. No se vuelve a codificar.
- Configura `MCP_ACCESS_KEY`: clave aleatoria privada de al menos 32 caracteres para proteger este conector. Debe ser diferente del token de Aliaddo.
- Endpoint: `https://aliaddo-caldas.onrender.com/mcp`
- Health: `/health`. Solo comprueba que el servidor funciona, no valida acceso a Aliaddo.

Sin ambas credenciales, MCP responde 503 y no consulta datos. El token de Aliaddo nunca se publica en GitHub ni se entrega al cliente MCP. La version 2.1 admite OAuth con PKCE y mantiene la clave Bearer para clientes como Gemini CLI.

## Gemini web / Spark

1. En Aplicaciones conectadas > Aplicaciones personalizadas, introduce el endpoint `/mcp` y pulsa Siguiente.
2. Deja vacios ID de cliente y Secreto de cliente: el servidor admite registro dinamico (DCR).
3. En la pantalla de autorizacion de **aliaddo-caldas.onrender.com**, revisa el destino y autoriza solo una solicitud que acabas de iniciar. Introduce `MCP_ACCESS_KEY` de Render, nunca el token de Aliaddo ni la clave de Google.
4. La aplicacion recibe credenciales OAuth limitadas a `invoices:read`; la clave original no se le entrega. Al volver a Gemini, revisa sus permisos y termina la conexion.

La disponibilidad final depende de la cuenta y region de Google. La autenticacion OAuth probada localmente no sustituye la prueba real con Gemini ni la validacion de la API de Aliaddo.

### Sesiones y almacenamiento

- `PUBLIC_URL` es el origen HTTPS publico (por defecto `https://aliaddo-caldas.onrender.com`). No se deriva de cabeceras de la solicitud.
- `OAUTH_STORE_FILE` indica el archivo de sesiones, por defecto `./data/oauth.enc`. Se cifra con una clave derivada de `MCP_ACCESS_KEY`; nunca debe subirse a GitHub.
- Este almacen es para **una sola instancia** del servidor. Para conservar autorizaciones tras despliegues/reemplazos en Render, requiere un disco persistente y una ruta en ese disco, o sustituirlo por una base de datos compartida. El plan gratuito no conserva este archivo en todos esos eventos: puede ser necesario volver a conectar Gemini. No se contrata ningun recurso de pago automaticamente.
- Los tokens de acceso duran una hora. Los de renovacion rotan, expiran como maximo a los 30 dias del permiso original y su reutilizacion revoca la sesion. `/revoke` revoca la familia completa.
- Las solicitudes de autorizacion duran 10 minutos y los codigos 2 minutos, de un solo uso. Estos pasos transitorios se reinician al reiniciar el proceso.
- Si cambias `MCP_ACCESS_KEY`, conserva la anterior para descifrar el archivo o configura un archivo OAuth nuevo para reiniciar todas las autorizaciones. No se recuperan silenciosamente archivos con cifrado invalido.
- El servidor incluye limites de registros e intentos. Para uso con varios usuarios o instancias se debe migrar a un proveedor OAuth y almacenamiento adecuados.

## Gemini CLI

Fusiona este fragmento con tu configuracion existente; no reemplaces otras entradas:

```json
{"mcpServers":{"aliaddo":{"httpUrl":"https://aliaddo-caldas.onrender.com/mcp","headers":{"Authorization":"Bearer ${ALIADDO_MCP_ACCESS_KEY}"},"timeout":120000}}}
```

`ALIADDO_MCP_ACCESS_KEY` es una variable local con la misma clave que `MCP_ACCESS_KEY` en Render. No escribas el secreto en este archivo ni en un chat.

Ejemplo: "Consulta las facturas de hoy en Colombia. Recorre las paginas hasta una vacia y verifica que no haya ids repetidos. Muestra numero, cliente, moneda, total y estado."

La consulta filtra por fecha de factura, no por momento de creacion. No calcula ventas netas ni mezcla monedas. En la primera prueba compara resultados con Aliaddo. La herramienta solicita paginas hasta una vacia porque el limite efectivo de la API puede diferir del solicitado. Si una pagina se repite, detente y reporta que el resultado esta incompleto.

## Pruebas

`npm ci` y `npm test`. Se usa Aliaddo simulado: los tests no necesitan secretos ni consultan datos reales.

Fuente API: https://docs.aliaddo.com/consultar-facturas-36444001e0
