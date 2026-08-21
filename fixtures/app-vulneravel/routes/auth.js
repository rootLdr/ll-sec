const router = require("express").Router();
const jwt = require("jsonwebtoken");

router.post("/login", (req, res) => {
  const token = jwt.sign({ sub: req.body.email }, "segredo123");
  res.cookie("session", token);
  res.json({ ok: true });
});

router.get("/me", (req, res) => {
  const payload = jwt.decode(req.headers.authorization);
  res.json(payload);
});

router.get("/verificar", (req, res) => {
  const p = jwt.verify(req.headers.authorization, KEY, { algorithms: ["none"] });
  res.json(p);
});

router.get("/sair", (req, res) => {
  res.redirect(req.query.next);
});

module.exports = router;
