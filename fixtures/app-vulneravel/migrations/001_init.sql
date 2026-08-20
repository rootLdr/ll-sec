create table public.pedidos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total numeric
);

alter table public.pedidos disable row level security;

create policy "leitura_geral" on public.pedidos
  for select using (true);

grant all on public.pedidos to public;
