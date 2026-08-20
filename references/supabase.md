# Supabase

O modelo de segurança do Supabase é quase todo **Row Level Security**. Se a RLS
estiver errada, nenhuma outra camada salva: a chave `anon` roda no navegador do
usuário e fala direto com o Postgres via PostgREST.

## A checagem que importa mais

Para **cada tabela** criada nas migrations, confirme que existe:

```sql
ALTER TABLE public.<tabela> ENABLE ROW LEVEL SECURITY;
```

Tabela sem essa linha, exposta no schema `public`, é leitura e escrita para
qualquer um com a URL do projeto — que é pública por natureza, está no bundle.

```bash
grep -rn "create table" --include=*.sql . | wc -l
grep -rn "enable row level security" --include=*.sql . | wc -l
```

Números diferentes = investigar quais tabelas ficaram de fora. Não conclua só
pela contagem (pode haver RLS aplicada pelo painel), mas use como ponto de
partida e diga no achado que a verificação foi pelo código.

## Policies que existem e não protegem

```sql
create policy "..." on t for select using (true);          -- não filtra nada
create policy "..." on t for all using (auth.role() = 'authenticated');  -- todo logado vê tudo
```

A policy correta amarra a linha ao dono:

```sql
using (auth.uid() = user_id)
```

Atenção ao `for all` combinado com `using` sem `with check`: o `using` governa
leitura/seleção das linhas afetadas, o `with check` governa o que pode ser
gravado. Sem `with check`, o usuário atualiza uma linha sua **passando o
`user_id` de outro** e transfere o registro.

## anon × service_role

- `SUPABASE_ANON_KEY` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`: pode ir ao cliente. É
  desenhada para isso, e a proteção real é a RLS.
- `SUPABASE_SERVICE_ROLE_KEY`: **ignora RLS por completo**. Só em servidor. Se
  aparecer em arquivo com `use client`, em `NEXT_PUBLIC_*`, ou em qualquer coisa
  que entre no bundle, é **Crítico** — banco inteiro aberto.

```bash
grep -rn "SERVICE_ROLE\|service_role" --include=*.ts --include=*.tsx --include=*.js .
grep -rn "NEXT_PUBLIC_.*SERVICE\|NEXT_PUBLIC_.*SECRET" .
```

## Outros pontos

- **Storage**: buckets também têm policies. Bucket público com upload liberado
  vira hospedagem de conteúdo alheio e vetor de XSS se servir HTML do mesmo domínio.
- **Funções**: `security definer` roda com o dono da função e **fura RLS de
  propósito**. Cada uma precisa validar autorização por dentro; procure
  `create function` + `security definer` e leia o corpo.
- **Edge Functions**: `verify_jwt = false` no `config.toml` deixa a função aberta.
- **Realtime**: a publicação respeita RLS, mas só se a RLS existir.
