# Verificações agnósticas de stack

Leia sempre. Vale mesmo quando o reconhecimento não identificou nada — e é
justamente aí que ela mais importa, porque o resto da skill fica cego.

## Onde a superfície costuma estar

Procure por nome e por padrão, não por caminho fixo:

- **Entrada de requisição**: qualquer coisa que leia `req`, `request`, `params`,
  `query`, `body`, `headers`, `cookies`, `FormData`, `searchParams`, `event`.
- **Saída para o usuário**: renderização de template, montagem de HTML, resposta
  JSON que ecoa entrada.
- **Fronteira de confiança**: onde o código decide *quem é* o usuário e *o que ele
  pode*. Se essa decisão acontece em mais de um lugar com regras diferentes, isso
  é achado por si só.
- **Configuração**: `.env*`, `*.config.*`, `docker-compose*`, `*.tf`, CI/CD.
  Segredo em pipeline vaza no log de build.

## Perguntas que valem em qualquer linguagem

1. **A autorização é verificada no servidor, toda vez?** Verificar no login e
   confiar depois é o erro clássico. Cada requisição precisa reprovar sozinha.
2. **O identificador do recurso vem do cliente?** Então a consulta precisa
   carregar o dono junto (`AND user_id = <sessão>`), não só o id.
3. **Dado que entra é tratado como dado?** Concatenação em SQL, shell, LDAP,
   XPath, template ou caminho de arquivo (`../../etc/passwd`) é a mesma família
   de falha com roupas diferentes.
4. **O que acontece no erro?** Stack trace na resposta entrega caminho, versão e
   estrutura interna. Mensagem de login que distingue "usuário não existe" de
   "senha errada" entrega a lista de usuários.
5. **O que é registrado em log?** Senha, token e CPF em log são vazamento com
   retenção garantida.
6. **Upload**: extensão validada só no cliente, arquivo servido do mesmo domínio,
   sem limite de tamanho, nome de arquivo usado direto no caminho.
7. **Rate limiting** em login, reset de senha e endpoints caros. Sem ele, força
   bruta e conta cara.

## Segredos fora do código

O arquivo limpo não prova nada se o histórico guarda a chave:

```bash
git log --all --full-history -- '*.env*' '*secret*' '*credential*' | head -40
git log -p --all -S 'BEGIN PRIVATE KEY' --oneline | head
```

Segredo no histórico é severidade **Alta** mesmo já removido do HEAD — quem
clonou tem a chave. A correção é rotacionar, não apagar o commit.

## Antes de classificar como Crítico

Crítico exige que a exploração aconteça **sem autenticação**. Se depende de estar
logado, é Alto. Se depende de a vítima clicar em algo, é Médio. Essa disciplina é
o que faz o operador confiar no vermelho quando ele aparece.
