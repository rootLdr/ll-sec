# Next.js (App Router e Pages Router)

O erro estrutural típico: confundir *onde o código roda*. No Next, a mesma
linguagem escreve cliente e servidor, e a fronteira é sutil.

## O que vaza para o navegador

- Tudo em arquivo com `"use client"` — inclusive o que ele importa.
- Qualquer variável `NEXT_PUBLIC_*`, sempre, mesmo em Server Component.
- Props passadas de Server para Client Component: viajam serializadas no HTML.
  Buscar o usuário com todos os campos no servidor e passar o objeto inteiro para
  um componente cliente entrega hash de senha e token no `__NEXT_DATA__`.

```bash
grep -rln "use client" app components | xargs grep -ln "SERVICE_ROLE\|SECRET\|PRIVATE_KEY" 2>/dev/null
grep -rn "NEXT_PUBLIC_[A-Z_]*\(SECRET\|KEY\|TOKEN\|PASSWORD\)" .
```

## Server Actions

Uma Server Action é um **endpoint HTTP público**. O `"use server"` não autentica
nada: qualquer pessoa pode chamá-la diretamente, com os argumentos que quiser,
sem passar pela sua interface.

Toda action precisa, por dentro dela mesma:

1. obter a sessão (`auth()`, `getServerSession()`, o que o projeto usar);
2. checar o papel/permissão;
3. validar os argumentos (Zod ou equivalente) — o tipo TypeScript não existe em runtime.

Action que confia em ter sido chamada por um botão que só admin vê é **Alto**:
esconder o botão não fecha o endpoint.

## Middleware

`middleware.ts` é conveniente e insuficiente sozinho:

- o `matcher` frequentemente deixa rotas de fora — leia o matcher e compare com a
  lista real de rotas protegidas;
- ele roda no Edge, sem acesso ao banco, então costuma checar só a existência do
  cookie, não o papel;
- Server Actions e route handlers precisam revalidar mesmo assim.

Middleware como **única** camada de autorização é achado.

## Route handlers

`app/api/**/route.ts` e `pages/api/**`: mesma disciplina de qualquer API —
autenticar, autorizar, validar entrada, filtrar por dono. `params.id` vindo da URL
direto para o `where` é IDOR.

## Outros pontos

- `images.remotePatterns` com `**` transforma o otimizador em proxy aberto (SSRF/abuso).
- `dangerouslySetInnerHTML` com conteúdo de banco ou de usuário: XSS.
- `redirect()` com destino vindo de `searchParams`: open redirect.
- Cabeçalhos de segurança (CSP, HSTS, `X-Content-Type-Options`) em `next.config`
  ou no proxy — ausência é **Baixo**, exceto quando há XSS confirmado, que sobe.
- `export const dynamic = "force-dynamic"` em rota autenticada evita cache
  compartilhado; página autenticada cacheada estaticamente pode servir dado de um
  usuário para outro (isso é **Alto** quando confirmado).
