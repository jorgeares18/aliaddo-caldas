# Aliaddo Caldas MCP

Servidor MCP Streamable HTTP de solo consulta, con la herramienta `consultar_facturas`.

## Render

- Build: `npm install`
- Start: `npm start`
- Configura `ALIADDO_TOKEN`: token de Mis datos > Integracion de Aliaddo, ya en el formato Bearer que entrega Aliaddo. No se vuelve a codificar.
- Configura `MCP_ACCESS_KEY`: clave aleatoria privada de al menos 32 caracteres para proteger este conector. Debe ser diferente del token de Aliaddo.
- Endpoint: `https://aliaddo-caldas.onrender.com/mcp`
- Health: `/health`. Solo comprueba que el servidor funciona, no valida acceso a Aliaddo.

Sin ambas credenciales, MCP responde 503 y no consulta datos. El token de Aliaddo nunca se publica en GitHub ni se entrega al cliente MCP. Esta version utiliza clave Bearer, no OAuth. Requiere un cliente que admita cabeceras HTTP personalizadas, como Gemini CLI. No se presupone compatibilidad con Gemini web/Spark.

## Gemini CLI

Fusiona este fragmento con tu configuracion existente; no reemplaces otras entradas:

```json
{"mcpServers":{"aliaddo":{"httpUrl":"https://aliaddo-caldas.onrender.com/mcp","headers":{"Authorization":"Bearer ${ALIADDO_MCP_ACCESS_KEY}"},"timeout":120000}}}
```

`ALIADDO_MCP_ACCESS_KEY` es una variable local con la misma clave que `MCP_ACCESS_KEY` en Render. No escribas el secreto en este archivo ni en un chat.

Ejemplo: "Consulta las facturas de hoy en Colombia. Recorre las paginas hasta una vacia y verifica que no haya ids repetidos. Muestra numero, cliente, moneda, total y estado."

La consulta filtra por fecha de factura, no por momento de creacion. No calcula ventas netas ni mezcla monedas. En la primera prueba compara resultados con Aliaddo. La herramienta solicita paginas hasta una vacia porque el limite efectivo de la API puede diferir del solicitado. Si una pagina se repite, detente y reporta que el resultado esta incompleto.

## Pruebas

`npm install` y `npm test`. Se usa Aliaddo simulado: los tests no necesitan secretos ni consultan datos reales.

Fuente API: https://docs.aliaddo.com/consultar-facturas-36444001e0
