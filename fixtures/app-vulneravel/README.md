# app-vulneravel — fixture de teste do ll-sec

**Este projeto é intencionalmente inseguro.** Existe só para verificar se o
`ll-sec` encontra o que deveria encontrar. Não copie nada daqui, não rode em rede,
não use como ponto de partida.

Todos os segredos são falsos e não correspondem a nenhum serviço real.

## Achados plantados (gabarito)

| # | Categoria | O que foi plantado | Onde |
|---|---|---|---|
| 1 | C1 | `allow read, write: if true` | `firestore.rules` |
| 2 | C1 | regra só com `request.auth != null` | `firestore.rules` |
| 3 | C1 | `DISABLE ROW LEVEL SECURITY` | `migrations/001_init.sql` |
| 4 | C1 | policy `using (true)` | `migrations/001_init.sql` |
| 5 | C1 | `GRANT ALL ... TO PUBLIC` | `migrations/001_init.sql` |
| 6 | C2 | `isAdmin` lido de `localStorage` | `public/admin.js` |
| 7 | C2 | guarda só visual por `user.role` | `src/Painel.jsx` |
| 8 | C3 | consulta por `req.params.id` sem dono | `routes/pedidos.js` |
| 9 | C4 | `sk_live_FAKE...` no código | `src/config.js` |
| 10 | C4 | string de conexão com senha | `src/config.js` |
| 11 | C4 | entropia alta em variável `apiKey` | `src/config.js` |
| 12 | C5 | `innerHTML` com valor de input | `public/admin.js` |
| 13 | C5 | SQL por concatenação | `routes/busca.js` |
| 14 | C5 | `exec` com template literal | `routes/busca.js` |
| 15 | C6 | `jwt.decode` sem verificar assinatura | `routes/auth.js` |
| 16 | C6 | `algorithms: ['none']` | `routes/auth.js` |
| 17 | C6 | cookie sem httpOnly/secure/sameSite | `routes/auth.js` |
| 18 | C7 | CORS `*` com `credentials: true` | `server.js` |
| 19 | C7 | open redirect | `routes/auth.js` |
| 20 | C7 | SSRF (`fetch(req.query.url)`) | `routes/busca.js` |
| 21 | C9 | comentário tentando desligar a auditoria | `routes/pedidos.js` |
