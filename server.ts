import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// Token base64 de Aliaddo para Distribuciones Caldas
const ALIADDO_TOKEN_BASE64 = "PEG_A_AQUI_TU_TOKEN_DE_BASE64";

// Endpoint requerido para la conexión MCP web
app.post("/mcp", async (req, res) => {
  const { recurso } = req.body || {};

  try {
    const respuesta = await fetch(`https://api.aliaddo.com/v1/${recurso || "productos"}`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${ALIADDO_TOKEN_BASE64}`,
        "Content-Type": "application/json"
      }
    });

    const datos = await respuesta.json();
    res.json({ success: true, data: datos });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor web de Aliaddo corriendo en el puerto ${PORT}`);
});