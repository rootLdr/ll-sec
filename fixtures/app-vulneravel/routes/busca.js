const router = require("express").Router();
const { exec } = require("child_process");
const db = require("../src/db");

router.get("/", async (req, res) => {
  const rows = await db.query("SELECT * FROM produtos WHERE nome LIKE '%" + req.query.q + "%'");
  res.json(rows);
});

router.get("/relatorio", (req, res) => {
  exec(`gerar-relatorio --formato ${req.query.formato}`, (e, out) => res.send(out));
});

router.get("/preview", async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

module.exports = router;
