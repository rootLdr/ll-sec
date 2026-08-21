# Node / Express / Fastify / Koa

## Ordem dos middlewares

A ordem é a segurança. Um `app.use(auth)` declarado **depois** das rotas não
protege nenhuma delas. Leia o arquivo principal de cima para baixo e monte a
sequência real: quais rotas são registradas antes do middleware de autenticação?

Rota registrada antes do guard = rota pública, mesmo que o nome diga `/admin`.

## CORS

```javascript
app.use(cors());                                    // origem "*"
app.use(cors({ origin: "*", credentials: true }));  // combinação inválida e perigosa
app.use(cors({ origin: req.headers.origin, credentials: true })); // reflexão = liberar todos
```

Com `credentials: true`, o navegador recusa `*` — e a resposta comum do
desenvolvedor é refletir o `Origin` recebido, o que é pior: qualquer site passa a
chamar sua API com o cookie da vítima. O certo é uma allowlist explícita.

## Sessão e cookie

```javascript
res.cookie("session", token, {
  httpOnly: true,   // sem isso, um XSS lê a sessão
  secure: true,     // sem isso, ela trafega em claro
  sameSite: "lax",  // sem isso, CSRF
  maxAge: ...       // sessão eterna é conta comprometida para sempre
});
```

`express-session` com `secret` fixo no código: qualquer um assina sessões.
Confira também se o logout invalida no servidor ou só apaga o cookie do cliente.

## Rotas e IDOR

```javascript
app.get("/api/pedidos/:id", auth, async (req, res) => {
  const p = await db.pedido.findUnique({ where: { id: req.params.id } }); // IDOR
  res.json(p);
});
```

O `auth` provou *quem* é, não *que aquele pedido é dele*. Correto:
`where: { id: req.params.id, userId: req.user.id }`.

## Injeção

- SQL: `db.query("... WHERE email = '" + email + "'")` → parametrizar.
- NoSQL: `find({ user: req.body.user })` com `{"$ne": null}` no corpo passa direto.
  Valide tipos; `$` e `.` em chaves de objeto vindo do usuário são bandeira.
- Comando: `exec(\`convert ${arquivo}\`)` → `execFile` com lista de argumentos.
- Caminho: `path.join(base, req.params.nome)` com `../` sai da pasta. Normalize e
  confirme que o resultado ainda começa com `base`.

## Outros pontos

- `helmet` ausente → cabeçalhos de segurança faltando (**Baixo**).
- Upload sem limite de tamanho/tipo; `req.files` gravado com o nome original.
- `express.json({ limit })` ausente → payload gigante derruba o processo.
- Erro devolvido com `err.stack` na resposta entrega estrutura interna.
- Sem rate limit em `/login` e `/reset`: força bruta.
