const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

app.use("/api/pedidos", require("./routes/pedidos"));
app.use("/api/busca", require("./routes/busca"));
app.use("/auth", require("./routes/auth"));

app.listen(3000);
