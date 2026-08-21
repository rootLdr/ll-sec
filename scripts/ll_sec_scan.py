#!/usr/bin/env python3
"""
ll-sec — varredura de segurança somente-leitura, portável entre projetos.

Faz o trabalho mecânico e determinístico da auditoria: reconhecimento de stack,
varredura por padrões, entropia, fingerprint, diff contra a execução anterior,
supressões e renderização do HTML. O julgamento fica com o agente, que lê o
JSON produzido aqui, confirma/descarta os achados lendo os arquivos e pode
acrescentar achados próprios antes de renderizar.

Só lê o repositório. As ÚNICAS escritas são dentro de <out> (pasta de
relatórios) e uma linha no .gitignore, ambas explícitas.

Uso:
  ll_sec_scan.py recon  --root .
  ll_sec_scan.py scan   --root . --mode rapida --out ./ll-sec-relatorios
  ll_sec_scan.py render --root . --out ./ll-sec-relatorios --findings <f.json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Reconhecimento
# --------------------------------------------------------------------------

IGNORAR_DIRS = {
    "node_modules", "vendor", "dist", "build", ".next", ".git", ".venv", "venv",
    "__pycache__", ".pytest_cache", "coverage", ".turbo", ".cache", "target",
    "bin", "obj", ".gradle", "Pods", ".terraform", "ll-sec-relatorios",
    ".agent-browser", ".svelte-kit", "out",
}

EXT_CODIGO = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".php", ".go", ".java", ".cs", ".kt", ".rs", ".sql", ".prisma",
    ".rules", ".json", ".yml", ".yaml", ".env", ".sh", ".tf", ".graphql",
}

ARQ_SEM_EXT = {"Dockerfile", "Procfile", "Makefile", ".env", ".npmrc"}

MARCADORES_STACK = [
    ("nextjs",      ["next.config.js", "next.config.ts", "next.config.mjs"]),
    ("node-express",["package.json"]),
    ("python",      ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"]),
    ("php-laravel", ["composer.json", "artisan"]),
    ("go",          ["go.mod"]),
    ("ruby",        ["Gemfile"]),
    ("dotnet",      []),
    ("supabase",    ["supabase/config.toml", "supabase"]),
    ("firebase",    ["firebase.json", "firestore.rules", "storage.rules"]),
    ("pocketbase",  ["pb_migrations"]),
    ("appwrite",    ["appwrite.json"]),
]


def detectar_stacks(root: Path) -> dict:
    """Reconhece linguagens, frameworks e BaaS sem assumir nada do projeto."""
    achados: list[str] = []
    detalhes: dict[str, list[str]] = {}

    for nome, marcadores in MARCADORES_STACK:
        for m in marcadores:
            if (root / m).exists():
                achados.append(nome)
                detalhes.setdefault(nome, []).append(m)
                break

    if list(root.glob("*.csproj")) or list(root.glob("**/*.csproj")):
        achados.append("dotnet")

    pkg = root / "package.json"
    deps: dict[str, str] = {}
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        except Exception:
            deps = {}
        for chave, nome in [
            ("next", "nextjs"), ("express", "node-express"), ("fastify", "node-express"),
            ("@supabase/supabase-js", "supabase"), ("firebase", "firebase"),
            ("firebase-admin", "firebase"), ("@prisma/client", "prisma"),
            ("nuxt", "nuxt"), ("@sveltejs/kit", "sveltekit"), ("koa", "node-express"),
        ]:
            if chave in deps:
                achados.append(nome)

    # Referências a ler: só as das stacks realmente detectadas, para o contexto
    # do agente não carregar documentação de framework que o projeto não usa.
    mapa_ref = {
        "supabase": "supabase.md", "firebase": "firebase.md",
        "nextjs": "nextjs.md", "node-express": "node-express.md",
        "python": "python.md", "php-laravel": "php-laravel.md",
    }
    stacks = sorted(set(achados))
    refs = sorted({mapa_ref[s] for s in stacks if s in mapa_ref}) or ["generico.md"]
    if "generico.md" not in refs:
        refs.append("generico.md")

    return {"stacks": stacks, "detalhes": detalhes, "referencias": refs,
            "reconhecido": bool(stacks)}


def listar_arquivos(root: Path, mode: str, since: str | None) -> tuple[list[Path], dict]:
    """Arquivos de código a varrer, já priorizados e com teto por modo."""
    cobertura = {"total_encontrados": 0, "varridos": 0, "cortados": 0, "motivo_corte": "",
                 "limitacoes": []}

    if mode == "diff":
        ref = since or "HEAD~1"
        try:
            # `check=True` de propósito: fora de um repositório Git o `git diff`
            # sai com 128 e stdout vazio. Sem isso, a lista vazia virava
            # "nenhum arquivo mudou" e a auditoria devolvia zero achado em
            # silêncio — o pior caminho de F1. O except abaixo, que sempre
            # existiu, era inalcançável justamente por causa disso.
            saida = subprocess.run(
                ["git", "-C", str(root), "diff", "--name-only", ref],
                capture_output=True, text=True, timeout=30, check=True,
            ).stdout
            alvos = [root / l.strip() for l in saida.splitlines() if l.strip()]
            arquivos = [p for p in alvos if p.is_file() and relevante(p)]
            cobertura["total_encontrados"] = len(arquivos)
            cobertura["varridos"] = len(arquivos)
            cobertura["ref_diff"] = ref
            return arquivos, cobertura
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError, OSError) as e:
            detalhe = (getattr(e, "stderr", "") or str(e)).strip().splitlines() or [""]
            motivo = (f"o modo diff foi pedido mas o `git diff {ref}` falhou "
                      f"({detalhe[0][:160]}); a execução caiu para varredura completa")
            cobertura["motivo_corte"] = motivo
            cobertura["limitacoes"].append(dict(
                tipo="modo_diff_indisponivel", descricao=motivo, afeta="todos", itens=[]))
            mode = "rapida"

    encontrados: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # `d != ".git"`, e não `startswith(".git")`: o prefixo comia `.github/` e
        # `.gitlab/` junto com o `.git/`, e workflow de CI é dos lugares mais
        # comuns para segredo em texto claro. Só o diretório do Git sai.
        dirnames[:] = [d for d in dirnames if d not in IGNORAR_DIRS and d != ".git"]
        for fn in filenames:
            p = Path(dirpath) / fn
            if relevante(p):
                encontrados.append(p)

    cobertura["total_encontrados"] = len(encontrados)
    encontrados.sort(key=lambda p: (prioridade(p, root), str(p)))

    teto = 1200 if mode == "completa" else 600
    if len(encontrados) > teto:
        cobertura["cortados"] = len(encontrados) - teto
        cobertura["motivo_corte"] = (
            f"repositório grande: varridos os {teto} arquivos de maior prioridade "
            f"(rotas/API → auth → banco/migrations → render de input → resto); "
            f"{len(encontrados) - teto} arquivos de menor prioridade ficaram de fora"
        )
        encontrados = encontrados[:teto]

    cobertura["varridos"] = len(encontrados)
    return encontrados, cobertura


def relevante(p: Path) -> bool:
    if any(parte in IGNORAR_DIRS for parte in p.parts):
        return False
    if p.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
                  "Gemfile.lock", "poetry.lock", "Cargo.lock"}:
        return False
    if p.name in ARQ_SEM_EXT or p.name.startswith(".env"):
        return True
    if p.suffix.lower() not in EXT_CODIGO:
        return False
    try:
        if p.stat().st_size > 800_000:
            return False
    except OSError:
        return False
    return True


def prioridade(p: Path, root: Path) -> int:
    """Menor número = varre primeiro. A ordem existe para que, quando o
    orçamento estourar, o que ficar de fora seja o menos perigoso."""
    s = str(p.relative_to(root)).lower() if p.is_relative_to(root) else str(p).lower()
    if any(k in s for k in ("route", "/api/", "controller", "handler", "endpoint", "resolver")):
        return 0
    if any(k in s for k in ("middleware", "auth", "session", "guard", "permission", "policy", "rbac")):
        return 1
    if any(k in s for k in ("migration", ".sql", "schema", ".rules", "prisma", "seed")):
        return 2
    if p.suffix in {".env"} or p.name.startswith(".env") or "config" in s:
        return 3
    if any(k in s for k in ("component", "page", "view", "template", "/src/")):
        return 4
    return 5


# --------------------------------------------------------------------------
# Regras
# --------------------------------------------------------------------------
# severidade segue a rubrica do operador:
#   critico      → explorável remotamente sem autenticação, ou segredo ativo exposto
#   alto         → explorável por usuário autenticado comum, ou segredo no histórico
#   medio        → exige condição adicional (config, vítima interagir)
#   baixo        → hardening ausente, sem vetor direto demonstrado
#   informativo  → suspeita não confirmada; sempre diz o que falta para confirmar

R = lambda p: re.compile(p, re.IGNORECASE)

REGRAS = [
    # ---------------- C1 — banco sem tranca / RLS ----------------
    dict(id="C1-firestore-aberto", cat="C1", sev="critico",
         titulo="Regra de banco liberada para qualquer um",
         rx=R(r"allow\s+(read|write|create|update|delete|read,\s*write)[^;]*:\s*if\s+true"),
         ext={".rules"},
         explica="A regra libera a operação sem nenhuma condição. Qualquer pessoa com o "
                 "endereço do projeto lê ou escreve o banco inteiro, sem login.",
         confirma="Abrir o arquivo de regras e verificar se essa cláusula está em produção."),
    dict(id="C1-firestore-so-logado", cat="C1", sev="alto",
         titulo="Regra exige apenas estar logado, sem checar dono do dado",
         rx=R(r"allow\s+(read|write|create|update|delete|read,\s*write)[^;]*:\s*if\s+request\.auth\s*!=\s*null\s*;"),
         ext={".rules"},
         explica="Qualquer usuário autenticado — inclusive um recém-cadastrado — alcança "
                 "os dados de todos os outros. Falta comparar o dono do documento.",
         confirma="Verificar se a coleção guarda dado de um usuário específico."),
    dict(id="C1-rls-desligada", cat="C1", sev="critico",
         titulo="Row Level Security desativada explicitamente",
         rx=R(r"alter\s+table\s+[^\s;]+\s+disable\s+row\s+level\s+security"),
         ext={".sql"},
         explica="Desligar RLS no Postgres do Supabase expõe a tabela inteira à chave "
                 "pública (anon), que roda no navegador do usuário.",
         confirma="Conferir se a tabela é alcançável pela API pública."),
    dict(id="C1-policy-permissiva", cat="C1", sev="alto",
         titulo="Policy de RLS com condição sempre verdadeira",
         rx=R(r"create\s+policy[\s\S]{0,200}?using\s*\(\s*true\s*\)"),
         ext={".sql"},
         explica="A policy existe mas não filtra nada: `using (true)` autoriza toda linha "
                 "para todo mundo. É RLS ligada com a porta escancarada.",
         confirma="Ver se a tabela contém dado de mais de um usuário/tenant."),
    dict(id="C1-grant-public", cat="C1", sev="alto",
         titulo="Permissão ampla concedida a PUBLIC",
         rx=R(r"grant\s+(all|select|insert|update|delete)[^;]{0,80}\bto\s+public\b"),
         ext={".sql"},
         explica="`TO PUBLIC` alcança qualquer papel do banco, inclusive o anônimo.",
         confirma="Checar quais papéis a aplicação expõe."),
    dict(id="C1-service-role-no-cliente", cat="C1", sev="critico",
         titulo="Chave de serviço (service_role) usada em código de cliente",
         rx=R(r"(service_role|SUPABASE_SERVICE_ROLE|serviceRoleKey|FIREBASE_ADMIN)"),
         ext={".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"},
         caminho_exige=R(r"(client|components?|pages?|app|public|frontend|src)"),
         caminho_nao=R(r"(server|api|route\.|actions?|lib/server|\.server\.)"),
         explica="A chave de serviço ignora RLS e toda regra de autorização. Se ela chega "
                 "ao navegador, o banco inteiro fica aberto para quem abrir o DevTools.",
         confirma="Confirmar se o arquivo roda mesmo no cliente (tem 'use client'? é bundle?)."),

    # ---------------- C2 — autorização no front-end ----------------
    dict(id="C2-role-no-storage", cat="C2", sev="alto",
         titulo="Papel/permissão lido de localStorage ou sessionStorage",
         rx=R(r"(localStorage|sessionStorage)\.(getItem\(\s*['\"][^'\"]*(admin|role|perm|is_?admin|nivel)|[a-z_]*\b(isAdmin|role))"),
         explica="O usuário edita localStorage em dois cliques. Se a permissão vem dali, "
                 "virar admin é digitar uma linha no console.",
         confirma="Ver se o servidor revalida esse papel antes de liberar a ação."),
    dict(id="C2-guard-so-visual", cat="C2", sev="medio",
         titulo="Permissão decidida no componente, possivelmente sem checagem no servidor",
         # `\w*\.` no meio é OPCIONAL de propósito: o caso mais comum é
         # `user.role === "admin"` (um ponto só). Exigir dois pontos fazia a
         # regra passar batido justamente na forma mais frequente.
         rx=R(r"(if\s*\(\s*(user|session|auth|me|currentUser)\??\.(\w+\.)?(is_?admin|role|nivel|perfil)\s*(===|==|!==|!=)"
              r"|\{\s*(user|session|auth|me|currentUser)\??\.(\w+\.)?(is_?admin|role|nivel|perfil)\s*(&&|\?))"),
         ext={".tsx", ".jsx", ".vue", ".svelte"},
         explica="Esconder o botão não protege a rota. Se o endpoint por trás não repetir a "
                 "checagem, basta chamar a API direto.",
         confirma="Localizar o endpoint correspondente e verificar se ele revalida o papel.",
         sev_se_servidor="informativo"),

    # ---------------- C3 — IDOR ----------------
    dict(id="C3-idor-consulta-por-id", cat="C3", sev="alto",
         titulo="Consulta por ID vindo da requisição sem filtro de dono",
         rx=R(r"(findUnique|findFirst|findOne|findById|get\()\s*\(?\s*\{?[^)}]{0,120}(id\s*:\s*(req\.|request\.|params\.|ctx\.params|searchParams))"),
         explica="O identificador vem do cliente e vira consulta direta. Trocar o número na "
                 "URL devolve o dado de outra pessoa (IDOR).",
         confirma="Verificar se a consulta também filtra por usuário/tenant da sessão."),
    dict(id="C3-idor-sql-por-id", cat="C3", sev="alto",
         titulo="SQL filtrando só por id vindo da requisição",
         rx=R(r"where\s+id\s*=\s*[\$'\"]?\s*(\+|\$\{|%s|\?)?[^;]{0,40}(req\.|request\.|params|query\[)"),
         explica="Mesma falha do IDOR, agora em SQL cru: sem cláusula de dono, o id do "
                 "cliente decide o que sai do banco.",
         confirma="Conferir se há `AND user_id = <sessão>` na mesma consulta."),

    # ---------------- C4 — segredos ----------------
    dict(id="C4-chave-conhecida", cat="C4", sev="critico",
         titulo="Chave de API com prefixo reconhecido no código",
         rx=R(r"\b(sk_live_[A-Za-z0-9]{8,}|sk_test_[A-Za-z0-9]{8,}|rk_live_[A-Za-z0-9]{8,}"
              r"|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}"
              r"|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
              r"|AIza[0-9A-Za-z_\-]{30,}|SG\.[A-Za-z0-9_\-]{16,}"
              r"|glpat-[A-Za-z0-9_\-]{16,})"),
         mascarar=True,
         explica="Segredo em texto claro no repositório. Se o repositório for compartilhado, "
                 "clonado ou publicado, a chave vaza junto — e chave viva é acesso, não risco teórico.",
         confirma="Verificar se a chave está ativa no painel do provedor e rotacionar."),
    dict(id="C4-chave-privada", cat="C4", sev="critico",
         titulo="Chave privada embutida no repositório",
         rx=R(r"-----BEGIN\s+(RSA|EC|OPENSSH|PGP|DSA)?\s*PRIVATE KEY-----"),
         mascarar=True,
         explica="Chave privada versionada. Serve para assinar, decifrar ou entrar em servidor.",
         confirma="Identificar o par público correspondente e revogar."),
    dict(id="C4-url-com-senha", cat="C4", sev="critico",
         titulo="String de conexão com usuário e senha embutidos",
         rx=R(r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:'\"/]+:[^\s@'\"]{4,}@"),
         mascarar=True,
         explica="Credencial de banco em texto claro, pronta para uso por quem ler o arquivo.",
         confirma="Conferir se o banco aceita conexão externa e trocar a senha."),
    dict(id="C4-jwt-literal", cat="C4", sev="alto",
         titulo="Token JWT literal no código",
         rx=R(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
         mascarar=True,
         explica="JWT gravado no código costuma ser token de serviço de longa validade.",
         confirma="Decodificar o payload (sem validar) e ver `exp` e escopo."),
    dict(id="C4-segredo-atribuido", cat="C4", sev="alto",
         titulo="Segredo atribuído diretamente a variável",
         rx=R(r"(?:const|let|var|final|val)?\s*\b\w*(secret|password|passwd|senha|api_?key|apikey|token|auth)\w*\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
         mascarar=True,
         ignora_valor=R(r"^(process\.env|import\.meta|os\.environ|env\.|<|\{\{|\$\{|xxx|todo|change|your|exemplo|example|placeholder|dummy|fake|test|redacted|\*+)"),
         explica="Valor fixo em variável com nome de segredo. Mesmo que hoje seja de teste, "
                 "o padrão é o que vaza credencial real amanhã.",
         confirma="Checar se o valor é usado contra um serviço real."),

    # ---------------- C5 — input sem sanitização / XSS ----------------
    dict(id="C5-innerhtml", cat="C5", sev="medio",
         titulo="HTML montado a partir de valor dinâmico",
         rx=R(r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\()"),
         explica="Se o valor vier do usuário, o navegador executa o script que ele mandar "
                 "(XSS) — sequestro de sessão, ação em nome da vítima.",
         confirma="Rastrear a origem do valor: veio de input, URL, banco ou é constante?"),
    dict(id="C5-dangerously", cat="C5", sev="medio",
         titulo="dangerouslySetInnerHTML / v-html com valor dinâmico",
         rx=R(r"(dangerouslySetInnerHTML|v-html\s*=)"),
         explica="A API existe para casos em que o HTML é confiável. Com valor de usuário, é XSS.",
         confirma="Ver se o conteúdo passa por sanitizador (DOMPurify, sanitize-html)."),
    dict(id="C5-eval", cat="C5", sev="alto",
         titulo="Execução dinâmica de código",
         rx=R(r"(\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*[`'\"]?\s*\$\{|setTimeout\s*\(\s*['\"])"),
         explica="Executar string como código transforma qualquer input em execução remota.",
         confirma="Verificar se a string tem qualquer parte controlada pelo usuário."),
    dict(id="C5-sql-concatenado", cat="C5", sev="critico",
         titulo="SQL montado por concatenação ou interpolação",
         rx=R(r"(query|execute|raw|prepare)\s*\(\s*[`'\"](?:[^`'\"]*?)(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,120}?(\+\s*\w|\$\{|%\s*\(|\bf['\"])"),
         explica="Injeção de SQL: o usuário passa a escrever parte da consulta. Dá para ler "
                 "tabela inteira, autenticar-se como outro ou apagar dados.",
         confirma="Confirmar que o trecho interpolado vem do usuário e trocar por parâmetro."),
    dict(id="C5-comando-shell", cat="C5", sev="critico",
         titulo="Comando de sistema montado com valor dinâmico",
         rx=R(r"(child_process\.)?(exec|execSync|spawnSync)\s*\(\s*[`'\"][^`'\"]*\$\{|os\.system\s*\(\s*f['\"]|subprocess\.\w+\([^)]*shell\s*=\s*True"),
         explica="Injeção de comando: o usuário emenda `; rm -rf` e o servidor obedece.",
         confirma="Ver a origem da variável e trocar por execução com lista de argumentos."),

    # ---------------- C6 — autenticação e sessão ----------------
    dict(id="C6-jwt-sem-verificacao", cat="C6", sev="critico",
         titulo="JWT decodificado sem verificar assinatura",
         rx=R(r"(jwt\.decode\s*\(|jwtDecode\s*\(|decodeJwt\s*\(|verify\s*:\s*false|verify_signature['\"]?\s*:\s*False)"),
         explica="Decodificar não é validar. Sem conferir a assinatura, qualquer pessoa forja "
                 "um token dizendo que é admin.",
         confirma="Ver se existe um `verify` com a chave em algum ponto do fluxo."),
    dict(id="C6-alg-none", cat="C6", sev="critico",
         titulo="Algoritmo 'none' aceito na validação de token",
         rx=R(r"algorithms?\s*[:=]\s*\[?\s*['\"]none['\"]"),
         explica="`alg: none` significa token sem assinatura: forjar é trivial.",
         confirma="Fixar a lista de algoritmos permitidos."),
    dict(id="C6-jwt-segredo-fixo", cat="C6", sev="alto",
         titulo="Segredo de assinatura de token embutido no código",
         rx=R(r"(jwt\.sign|jsonwebtoken|encode)\s*\([\s\S]{0,120}['\"][A-Za-z0-9_\-!@#$%^&*]{4,}['\"]\s*[,)]"),
         mascarar=True,
         ignora_valor=R(r"process\.env|os\.environ|import\.meta"),
         explica="Quem lê o repositório assina tokens válidos — inclusive de outro usuário.",
         confirma="Mover para variável de ambiente e invalidar tokens emitidos."),
    dict(id="C6-cookie-inseguro", cat="C6", sev="baixo",
         titulo="Cookie de sessão sem httpOnly/secure/sameSite",
         rx=R(r"(res\.cookie|cookies\(\)\.set|setCookie|document\.cookie\s*=)"),
         explica="Sem `httpOnly` um XSS lê a sessão; sem `secure` ela trafega em claro; sem "
                 "`sameSite` fica exposta a CSRF.",
         confirma="Ler as opções passadas na chamada e confirmar as três flags."),

    # ---------------- C7 — CSRF, CORS, headers, redirect, SSRF ----------------
    dict(id="C7-cors-aberto", cat="C7", sev="alto",
         titulo="CORS liberado para qualquer origem",
         rx=R(r"(origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|cors\(\s*\)|origin\s*:\s*true)"),
         explica="Origem `*` combinada com credenciais deixa qualquer site chamar a API "
                 "com o cookie da vítima.",
         confirma="Verificar se `credentials: true` está junto — aí a severidade sobe."),
    dict(id="C7-cors-refletido", cat="C7", sev="alto",
         titulo="Origem do requisitante refletida sem allowlist",
         rx=R(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*(req|request)\.(headers)?[\.\[]"),
         explica="Refletir o `Origin` recebido equivale a liberar todo mundo, só que "
                 "passando pela checagem do navegador.",
         confirma="Conferir se há lista de origens permitidas antes da reflexão."),
    dict(id="C7-open-redirect", cat="C7", sev="medio",
         titulo="Redirecionamento para destino controlado pelo usuário",
         rx=R(r"(redirect|location)\s*\(?\s*=?\s*(req|request)\.(query|params|body)"),
         explica="Open redirect: o atacante manda um link do seu domínio que joga a vítima "
                 "no site dele. Base clássica de phishing.",
         confirma="Verificar se o destino é validado contra uma allowlist."),
    dict(id="C7-ssrf", cat="C7", sev="alto",
         titulo="Requisição do servidor para URL vinda do usuário (SSRF)",
         rx=R(r"(fetch|axios\.(get|post)|requests\.(get|post)|urlopen|HttpClient)\s*\(\s*(req|request)\.(query|body|params)"),
         explica="O servidor busca a URL que o usuário mandar — inclusive endereços internos "
                 "e metadados de nuvem (169.254.169.254).",
         confirma="Ver se há validação de esquema e host antes da chamada."),
    dict(id="C7-mutacao-por-get", cat="C7", sev="medio",
         titulo="Operação que altera estado exposta em GET",
         rx=R(r"\.get\s*\(\s*['\"][^'\"]*(delete|remove|create|update|add|set|reset|drop)[^'\"]*['\"]"),
         explica="Mudar estado por GET é acionável por uma tag de imagem em outro site (CSRF), "
                 "e ainda pode ser disparado por pré-carregamento do navegador.",
         confirma="Confirmar que o handler realmente escreve."),

    # ---------------- C9 — tentativa de manipular a auditoria ----------------
    dict(id="C9-prompt-injection", cat="C9", sev="alto",
         titulo="Texto no repositório tentando direcionar a análise da IA",
         rx=R(r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
              r"|ignore\s+(este|esse)\s+arquivo"
              r"|(este|esse)\s+(arquivo|c[óo]digo)\s+j[áa]\s+(foi|est[áa])\s+auditad"
              r"|n[ãa]o\s+(reporte|relate|inclua)\s+(este|esse|isto)"
              r"|do\s+not\s+report\s+this"
              r"|(this|the)\s+(file|code)\s+(is|has been)\s+(safe|audited|reviewed)\s*[,.:]?\s*(skip|ignore)"
              r"|\bAI\s*[:,]\s*(ignore|skip|do not)"
              r"|(claude|chatgpt|assistant)\s*[:,]\s*(ignore|skip|desconsidere))"),
         explica="Conteúdo do repositório tentando instruir a auditoria a se calar. Texto lido "
                 "de arquivo é DADO, não ordem — a instrução foi ignorada e o trecho virou achado. "
                 "Ou alguém está escondendo algo, ou o repositório recebeu conteúdo de terceiro "
                 "sem revisão; os dois merecem explicação.",
         confirma="Ler o arquivo inteiro e descobrir quem introduziu o trecho (git blame)."),
]


# --------------------------------------------------------------------------
# Entropia (reforço do C4)
# --------------------------------------------------------------------------

RX_ATRIBUICAO = re.compile(
    r"\b(\w*(?:key|secret|token|password|senha|api|auth|cred)\w*)\s*[:=]\s*['\"]([^'\"\s]{20,})['\"]",
    re.IGNORECASE,
)


def entropia_shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def mascarar(valor: str) -> str:
    """Segredo nunca sai inteiro no relatório — o relatório também vaza."""
    v = valor.strip()
    if len(v) <= 10:
        return "*" * len(v)
    return f"{v[:6]}{'*' * 8}{v[-4:]}"


# --------------------------------------------------------------------------
# Varredura
# --------------------------------------------------------------------------

def normalizar(trecho: str) -> str:
    """Normaliza o trecho para o fingerprint sobreviver a reindentação e a
    edições vizinhas — por isso o número da linha fica de fora."""
    return re.sub(r"\s+", " ", trecho.strip())[:200]


def fingerprint(regra_id: str, rel: str, trecho: str) -> str:
    base = f"{regra_id}|{rel}|{normalizar(trecho)}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def varrer(root: Path, arquivos: list[Path], stacks: list[str]) -> list[dict]:
    achados: list[dict] = []
    vistos: set[str] = set()

    for p in arquivos:
        try:
            texto = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        linhas = texto.splitlines()
        eh_teste = bool(re.search(r"(test|spec|fixture|mock|__tests__|example)", rel, re.I))

        for regra in REGRAS:
            if "ext" in regra and p.suffix.lower() not in regra["ext"]:
                continue
            if "caminho_exige" in regra and not regra["caminho_exige"].search(rel):
                continue
            if "caminho_nao" in regra and regra["caminho_nao"].search(rel):
                continue

            for m in regra["rx"].finditer(texto):
                linha_n = texto.count("\n", 0, m.start()) + 1
                trecho = linhas[linha_n - 1].strip() if linha_n <= len(linhas) else m.group(0)

                if "ignora_valor" in regra and regra["ignora_valor"].search(trecho):
                    continue

                fp = fingerprint(regra["id"], rel, trecho)
                if fp in vistos:
                    continue
                vistos.add(fp)

                sev = regra["sev"]
                nota = ""
                # Achado em teste/fixture continua sendo achado, mas não pode
                # competir em severidade com o mesmo padrão em produção.
                if eh_teste and sev in ("critico", "alto"):
                    sev = "medio" if sev == "critico" else "baixo"
                    nota = "Rebaixado: o caminho indica arquivo de teste/fixture, não produção."

                achados.append(dict(
                    fingerprint=fp, regra=regra["id"], categoria=regra["cat"],
                    severidade=sev, titulo=regra["titulo"], arquivo=rel, linha=linha_n,
                    trecho=mascarar(trecho) if regra.get("mascarar") else trecho[:300],
                    explicacao=regra["explica"], como_confirmar=regra["confirma"],
                    nota=nota, origem="padrao", estado="novo",
                ))

        # entropia — só informativo, para não inflar falso positivo
        for m in RX_ATRIBUICAO.finditer(texto):
            nome, valor = m.group(1), m.group(2)
            if re.match(r"^(process\.env|import\.meta|os\.environ|https?://|\$\{|\{\{|<)", valor):
                continue
            ent = entropia_shannon(valor)
            if ent < 4.0:
                continue
            linha_n = texto.count("\n", 0, m.start()) + 1
            trecho = linhas[linha_n - 1].strip() if linha_n <= len(linhas) else m.group(0)
            fp = fingerprint("C4-entropia", rel, trecho)
            if fp in vistos:
                continue
            vistos.add(fp)
            achados.append(dict(
                fingerprint=fp, regra="C4-entropia", categoria="C4", severidade="informativo",
                titulo=f"String de alta entropia em variável chamada '{nome}'",
                arquivo=rel, linha=linha_n, trecho=mascarar(trecho),
                explicacao=f"Entropia {ent:.2f} bits/char em {len(valor)} caracteres. O formato "
                           "parece de segredo, mas só a aparência não prova nada.",
                como_confirmar="Verificar se o valor é usado contra um serviço real; se for hash, "
                               "id público ou dado de teste, suprimir com justificativa.",
                nota="", origem="entropia", estado="novo",
            ))

    achados.extend(checar_permissao_arquivos_de_segredo(root))
    achados.extend(checar_arquivos_ilegiveis(root))

    ordem = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3, "informativo": 4}
    achados.sort(key=lambda a: (ordem[a["severidade"]], a["categoria"], a["arquivo"]))
    return achados


def checar_arquivos_ilegiveis(root: Path) -> list[dict]:
    """Arquivo de segredo que EXISTE mas o scanner não conseguiu abrir.

    Existe uma armadilha aqui que já enganou uma execução real: fechar a
    permissão de um .env (o certo a fazer) tira o arquivo do alcance do próprio
    auditor, e os achados que estavam nele simplesmente somem do relatório. Sem
    este aviso, o desaparecimento se lê como "resolvido" quando na verdade é
    "não olhado" — que é o oposto do que a auditoria promete.
    """
    achados: list[dict] = []
    for p in sorted(root.glob(".env*")) + sorted(root.glob("*.pem")) + sorted(root.glob("*.key")):
        nome = p.name
        if not p.is_file() or any(nome.endswith(suf) for suf in
                                  (".example", ".sample", ".template", ".dist")):
            continue
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                fh.read(1)
            continue
        except PermissionError:
            pass
        except OSError:
            continue

        achados.append(dict(
            fingerprint=fingerprint("C4-arquivo-ilegivel", nome, "sem permissao de leitura"),
            regra="C4-arquivo-ilegivel", categoria="C4", severidade="informativo",
            titulo=f"{nome} não pôde ser lido nesta execução (permissão)",
            arquivo=nome, linha=0, trecho="PermissionError ao abrir o arquivo",
            simples=(f"O {nome} existe, mas esta auditoria não conseguiu abri-lo — a permissão está "
                     "fechada, o que é o certo do ponto de vista de segurança. Só saiba que o "
                     "conteúdo dele NÃO foi verificado aqui: ausência de achado não é aprovação."),
            explicacao=("Fechar a permissão do arquivo tira também o auditor do alcance. Achados que "
                        "existiam nele desaparecem do relatório sem que nada tenha sido corrigido."),
            correcao=("Para auditar o conteúdo, rodar a skill como o dono do arquivo (ou com sudo) — "
                      "sem afrouxar a permissão."),
            quem="operador",
            como_confirmar=f"`ls -l {nome}` mostra o dono; rodar a auditoria com esse usuário cobre o conteúdo.",
            nota="", origem="cobertura", estado="novo",
        ))
    return achados


def checar_permissao_arquivos_de_segredo(root: Path) -> list[dict]:
    """Arquivo de segredo legível por qualquer conta da máquina.

    Não é varredura de conteúdo: é o modo do arquivo. Guardar segredo em .env
    fora do Git é o certo, mas o arquivo nasce com o padrão do sistema (costuma
    ser 644/664), e aí qualquer usuário com shell na máquina lê as chaves sem
    ser dono nem root. É o furo que sobra depois que todo o resto foi feito.

    Só olha arquivos REAIS de segredo — .example e .sample são modelo público
    e existem para ser lidos.
    """
    achados: list[dict] = []
    for p in sorted(root.glob(".env*")) + sorted(root.glob("*.pem")) + sorted(root.glob("*.key")):
        nome = p.name
        if not p.is_file():
            continue
        if any(nome.endswith(suf) for suf in (".example", ".sample", ".template", ".dist")):
            continue
        try:
            modo = p.stat().st_mode & 0o777
        except OSError:
            continue
        # Interessa o que "outros" e "grupo" enxergam; o dono sempre lê.
        if not (modo & 0o077):
            continue

        quem_le = []
        if modo & 0o070:
            quem_le.append("o grupo")
        if modo & 0o007:
            quem_le.append("qualquer usuário da máquina")

        achados.append(dict(
            fingerprint=fingerprint("C4-permissao-arquivo-segredo", nome, "modo do arquivo"),
            regra="C4-permissao-arquivo-segredo", categoria="C4", severidade="medio",
            titulo=f"{nome} legível além do dono (modo {oct(modo)[2:]})",
            arquivo=nome, linha=0, trecho=f"modo {oct(modo)[2:]} — esperado 600",
            simples=("O arquivo com as senhas e chaves está com permissão aberta: "
                     + " e ".join(quem_le)
                     + " consegue abrir e ler tudo, sem ser você e sem ser administrador."),
            explicacao=("Guardar segredo em arquivo .env fora do Git é o padrão correto, mas o "
                        "arquivo herda a permissão padrão do sistema ao ser criado. Ferramenta que "
                        "recria o arquivo (deploy, script, container) devolve a permissão aberta, "
                        "então isto merece ser conferido de tempos em tempos, não só uma vez."),
            correcao=f"chmod 600 {nome}",
            quem="operador",
            como_confirmar=f"`ls -l {nome}` deve mostrar -rw------- e nada além disso.",
            nota="", origem="permissao", estado="novo",
        ))
    return achados


# --------------------------------------------------------------------------
# Estado, diff e supressões
# --------------------------------------------------------------------------

def carregar_supressoes(root: Path) -> dict[str, str]:
    """`.ll-sec-ignore`: um fingerprint por linha + justificativa. A skill lê,
    nunca escreve — aceitar risco é decisão do operador, não da ferramenta."""
    arq = root / ".ll-sec-ignore"
    sup: dict[str, str] = {}
    if not arq.exists():
        return sup
    for linha in arq.read_text(encoding="utf-8", errors="replace").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = re.split(r"[\s|]+", linha, maxsplit=1)
        sup[partes[0]] = partes[1].strip() if len(partes) > 1 else "(sem justificativa)"
    return sup


def aplicar_diff(achados: list[dict], estado_path: Path) -> dict:
    anterior: set[str] = set()
    primeira = True
    if estado_path.exists():
        try:
            dados = json.loads(estado_path.read_text(encoding="utf-8"))
            anterior = set(dados.get("fingerprints", []))
            primeira = False
        except Exception:
            primeira = True

    atuais = {a["fingerprint"] for a in achados}
    for a in achados:
        if a.get("estado") == "conhecido":
            continue  # triagem persistente já classificou; não é novidade
        a["estado"] = "persistente" if a["fingerprint"] in anterior else "novo"

    resolvidos = sorted(anterior - atuais)
    return {"primeira_execucao": primeira, "novos": len([a for a in achados if a["estado"] == "novo"]),
            "persistentes": len([a for a in achados if a["estado"] == "persistente"]),
            "conhecidos": len([a for a in achados if a["estado"] == "conhecido"]),
            "resolvidos": len(resolvidos), "fingerprints_resolvidos": resolvidos}


def garantir_gitignore(root: Path, pasta: str) -> str:
    """O relatório é um mapa de vulnerabilidades: se vazar, é presente para o
    atacante. Esta é a única escrita permitida fora da pasta de relatórios."""
    gi = root / ".gitignore"
    alvo = pasta.rstrip("/") + "/"
    if gi.exists():
        conteudo = gi.read_text(encoding="utf-8", errors="replace")
        if alvo in conteudo or pasta in conteudo.split():
            return "ja_estava"
        with gi.open("a", encoding="utf-8") as f:
            f.write(f"\n# ll-sec — relatorios de seguranca (mapa de vulnerabilidades). NUNCA versionar.\n{alvo}\n")
        return "adicionado"
    gi.write_text(f"# ll-sec — relatorios de seguranca. NUNCA versionar.\n{alvo}\n", encoding="utf-8")
    return "criado"


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:26px;margin:0 0 4px;color:#f0f6fc}
.sub{color:#8b949e;font-size:13px;margin-bottom:22px}
.meta{display:flex;flex-wrap:wrap;gap:10px 26px;padding:14px 18px;background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:22px;font-size:13px}
.meta b{color:#f0f6fc;font-weight:600}
.placar{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:22px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 16px;text-align:center}
.card .n{font-size:30px;font-weight:700;line-height:1.1}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8b949e;margin-top:4px}
.critico{color:#ff7b72}.alto{color:#ffa657}.medio{color:#e3b341}.baixo{color:#79c0ff}.informativo{color:#8b949e}
.diff{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:26px}
.diff .card{border-left:3px solid #30363d}
.novo{border-left-color:#ff7b72!important}.persist{border-left-color:#e3b341!important}.resolv{border-left-color:#3fb950!important}
.tabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid #30363d;margin-bottom:18px}
.tab{padding:9px 15px;cursor:pointer;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;font-size:13px;color:#8b949e;user-select:none}
.tab:hover{color:#c9d1d9;background:#161b22}
.tab.on{background:#161b22;border-color:#30363d;color:#f0f6fc;font-weight:600}
.tab-ok{color:#7ee787}
.nota-ok{background:#0f2f1c;border:1px solid #3fb950;border-radius:9px;padding:12px 16px;margin-bottom:14px;font-size:13px;color:#a6e6b8}
.item.positivo{border-left-color:#3fb950}
.painel{display:none}.painel.on{display:block}
.item{background:#161b22;border:1px solid #30363d;border-left-width:4px;border-radius:9px;padding:15px 18px;margin-bottom:13px}
.item.s-critico{border-left-color:#ff7b72}.item.s-alto{border-left-color:#ffa657}
.item.s-medio{border-left-color:#e3b341}.item.s-baixo{border-left-color:#79c0ff}
.item.s-informativo{border-left-color:#484f58}
.tit{font-size:15px;font-weight:600;color:#f0f6fc;margin:0 0 7px}
.num{display:inline-block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;font-weight:700;color:#0d1117;background:#79c0ff;border-radius:6px;padding:1px 7px;margin-right:7px;vertical-align:1px}
.tags{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:9px}
.tag{font-size:11px;padding:2px 8px;border-radius:20px;background:#21262d;border:1px solid #30363d;color:#8b949e}
.nota-sel{font-weight:700;letter-spacing:.3px}
.nota-sel.n5{background:#3d1418;border-color:#ff7b72;color:#ff9f96}
.nota-sel.n4{background:#3a2411;border-color:#ffa657;color:#ffc08a}
.nota-sel.n3{background:#332b0f;border-color:#e3b341;color:#f0d074}
.nota-sel.n2{background:#0d2d4d;border-color:#79c0ff;color:#a5d6ff}
.nota-sel.n1{background:#21262d;border-color:#484f58;color:#8b949e}
.leg-c .nota-sel{display:inline-block;padding:2px 9px;border-radius:20px;border:1px solid}
.tag.sev-critico{background:#3d1418;border-color:#ff7b72;color:#ff9f96}
.tag.sev-alto{background:#3a2411;border-color:#ffa657;color:#ffc08a}
.tag.sev-medio{background:#332b0f;border-color:#e3b341;color:#f0d074}
.tag.sev-baixo{background:#0d2d4d;border-color:#79c0ff;color:#a5d6ff}
.tag.est-novo{background:#3d1418;border-color:#f85149;color:#ff9f96}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#79c0ff;margin-bottom:9px;word-break:break-all}
pre{background:#0d1117;border:1px solid #30363d;border-radius:7px;padding:11px 13px;overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#e6edf3;margin:0 0 10px}
.exp{font-size:13.5px;color:#c9d1d9;margin-bottom:8px}
.simples{font-size:13.5px;color:#d2e3f7;background:#12233a;border-left:3px solid #388bfd;border-radius:0 7px 7px 0;padding:9px 13px;margin-bottom:9px}
.simples b{color:#a5d6ff}
.fix{display:flex;flex-wrap:wrap;align-items:baseline;gap:9px;margin-bottom:9px;font-size:13px}
.fix-txt{flex:1;min-width:220px;color:#c9d1d9}
.selo{font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;white-space:nowrap}
.q-agente{background:#0f2f1c;border:1px solid #3fb950;color:#7ee787}
.q-operador{background:#3a2411;border:1px solid #ffa657;color:#ffc08a}
.q-ambos{background:#0d2d4d;border:1px solid #79c0ff;color:#a5d6ff}
.q-nenhuma{background:#21262d;border:1px solid #30363d;color:#8b949e}
.legenda{margin-bottom:20px}
.legenda summary{font-size:14px}
.tab-leg{margin-top:12px}
.tab-leg td{vertical-align:top;font-size:12.5px}
.leg-c{font-family:ui-monospace,Menlo,monospace;color:#79c0ff;font-weight:600;width:44px}
.leg-n{color:#f0f6fc;font-weight:600;white-space:nowrap}
.leg-m{white-space:nowrap;width:104px}
.leg-on{background:#1b1f26}
.pt-sim{font-size:11px;padding:2px 8px;border-radius:20px;background:#332b0f;border:1px solid #e3b341;color:#f0d074}
.pt-nao{font-size:11px;padding:2px 8px;border-radius:20px;background:#21262d;border:1px solid #30363d;color:#8b949e}
.leg-rod{font-size:12px;color:#8b949e;margin:11px 0 0}
.conf{font-size:12.5px;color:#8b949e;border-left:2px solid #30363d;padding-left:11px}
.nota{font-size:12px;color:#e3b341;margin-top:7px}
.vazio{padding:34px;text-align:center;color:#8b949e;background:#161b22;border:1px solid #30363d;border-radius:10px}
details{background:#161b22;border:1px solid #30363d;border-radius:9px;padding:12px 16px;margin-bottom:12px}
summary{cursor:pointer;font-weight:600;color:#f0f6fc}
.rodape{margin-top:34px;padding-top:18px;border-top:1px solid #30363d;font-size:12px;color:#8b949e}
.aviso{background:#3d1418;border:1px solid #f85149;border-radius:9px;padding:13px 17px;margin-bottom:22px;font-size:13.5px;color:#ffb3ab}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:7px 10px;border-bottom:1px solid #21262d;text-align:left}
th{color:#8b949e;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px}
@media print{body{background:#fff;color:#000}.tab{display:none}.painel{display:block!important}
.item,.card,.meta,details{background:#fff;border-color:#ccc;break-inside:avoid}
.tit,h1{color:#000}pre{background:#f6f8fa;color:#000}
.simples{background:#f0f6ff;color:#000}.simples b{color:#000}
.num{background:#e6edf3;color:#000;border:1px solid #999}
.selo{color:#000;background:#f6f8fa}.leg-n,.leg-c{color:#000}.leg-on{background:#f6f8fa}}
"""

JS = """
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on')});
    document.querySelectorAll('.painel').forEach(function(x){x.classList.remove('on')});
    t.classList.add('on');
    var el = document.getElementById(t.dataset.alvo);
    if (el) el.classList.add('on');
  });
});
"""

# Cada categoria carrega quatro coisas:
#   nome     — rótulo curto, usado na aba e na etiqueta do achado
#   simples  — o que é, em uma frase, para quem não é da área
#   correcao — o caminho de correção típico dessa família
#   quem     — quem consegue aplicar essa correção:
#              "agente"   = o Claude faz sozinho, é mudança de código
#              "operador" = exige você (senha, chave, serviço externo, decisão)
#              "ambos"    = o Claude prepara o código, você conclui fora dele
CATEGORIAS = {
    "C1": dict(nome="Banco sem tranca",
               simples="O banco aceita ler ou gravar sem checar quem está pedindo.",
               correcao="Ligar a trava de acesso por linha (RLS/regras) e escrever a condição de dono.",
               quem="ambos"),
    "C2": dict(nome="Permissão só na tela",
               simples="O sistema esconde o botão, mas o servidor não confere de novo — quem chamar direto passa.",
               correcao="Checar sessão e papel dentro da função do servidor, não só na tela.",
               quem="agente"),
    "C3": dict(nome="Dado de outro cliente",
               simples="Trocando um número no endereço, dá para ver o dado de outra pessoa.",
               correcao="Filtrar a consulta pelo dono, e não só pelo id que veio da requisição.",
               quem="agente"),
    "C4": dict(nome="Segredos expostos",
               simples="Senha, chave ou token aparecendo no código, onde não deviam estar.",
               correcao="Tirar do código e ler de variável de ambiente — e trocar o segredo, porque o antigo já vazou.",
               quem="ambos"),
    "C5": dict(nome="Entrada sem tratamento",
               simples="Texto digitado pelo usuário vira comando ou HTML sem ser tratado antes.",
               correcao="Validar e escapar a entrada; nunca montar SQL, HTML ou comando concatenando texto.",
               quem="agente"),
    "C6": dict(nome="Login e sessão",
               simples="A forma de provar quem você é pode ser falsificada ou roubada.",
               correcao="Verificar assinatura do token, segredo forte fora do código, cookie com flags.",
               quem="ambos"),
    "C7": dict(nome="CORS, CSRF e cabeçalhos",
               simples="Outro site consegue agir em nome do usuário, ou faltam proteções básicas no navegador.",
               correcao="Restringir origens, exigir token anti-CSRF e ligar os cabeçalhos de segurança.",
               quem="agente"),
    "C8": dict(nome="Dependência vulnerável",
               simples="Uma biblioteca usada pelo projeto tem falha conhecida e publicada.",
               correcao="Atualizar a biblioteca para a versão corrigida e rodar os testes.",
               quem="agente"),
    "C9": dict(nome="Manipulação da auditoria",
               simples="Tem texto no próprio código tentando mandar a auditoria ignorar algo.",
               correcao="Não há correção técnica: é decisão sua sobre quem escreveu aquilo e por quê.",
               quem="operador"),
}

SELO_QUEM = {
    "agente": ("q-agente", "O agente corrige sozinho"),
    "operador": ("q-operador", "Só você pode aplicar"),
    "ambos": ("q-ambos", "O agente prepara, você conclui"),
    "nenhuma": ("q-nenhuma", "Nada a corrigir"),
}


def cat_nome(c: str) -> str:
    return CATEGORIAS.get(c, {}).get("nome", "")

SEVS = ["critico", "alto", "medio", "baixo", "informativo"]

# Nota de 1 a 5 — 5 é o pior. A régua é sempre a MESMA das severidades: o que
# define a nota é quem consegue explorar a falha, não o quanto ela parece grave.
# Na dúvida entre duas notas, vale a menor, com o que falta para confirmar escrito
# no achado: relatório inflado ensina o operador a ignorar o relatório.
NOTAS = {
    "critico": dict(nota=5, rotulo="Crítico",
                    desc="Alguém de fora, sem senha nenhuma, consegue entrar, roubar ou sequestrar "
                         "os dados. É o pior caso — para tudo e resolve."),
    "alto": dict(nota=4, rotulo="Alto",
                 desc="Quem já tem login comum consegue chegar em dado que não é dele ou virar "
                      "administrador. Também entra aqui segredo que ficou gravado no histórico do Git."),
    "medio": dict(nota=3, rotulo="Médio",
                  desc="Dá para explorar, mas depende de uma condição a mais: uma configuração "
                       "específica, ou a vítima clicar em alguma coisa."),
    "baixo": dict(nota=2, rotulo="Baixo",
                  desc="Falta uma proteção que devia existir, mas não há caminho de ataque "
                       "demonstrado. É arrumação, não incêndio."),
    "informativo": dict(nota=1, rotulo="Informativo",
                        desc="Suspeita não confirmada, ou registro para constar. Sempre vem com o "
                             "que falta para virar achado de verdade."),
}


def nota_de(a: dict) -> int:
    return NOTAS.get(a.get("severidade", "informativo"), NOTAS["informativo"])["nota"]


def esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def render_item(a: dict) -> str:
    cat = CATEGORIAS.get(a["categoria"], {})
    info_nota = NOTAS.get(a["severidade"], NOTAS["informativo"])
    tags = [f'<span class="tag nota-sel n{info_nota["nota"]}">NOTA {info_nota["nota"]} · '
            f'{esc(info_nota["rotulo"])}</span>',
            f'<span class="tag">{a["categoria"]} · {esc(cat.get("nome", ""))}</span>',
            f'<span class="tag">{esc(a["regra"])}</span>']
    if a.get("estado") == "novo":
        tags.append('<span class="tag est-novo">NOVO</span>')
    elif a.get("estado") == "persistente":
        tags.append('<span class="tag">persistente</span>')
    elif a.get("estado") == "conhecido":
        rot = a.get("triado_em") or "execução anterior"
        tags.append(f'<span class="tag">conhecido desde {esc(rot)}</span>')
    tags.append(f'<span class="tag">fp {esc(a["fingerprint"])}</span>')
    nota = f'<div class="nota">{esc(a["nota"])}</div>' if a.get("nota") else ""

    # Em português claro — o achado pode trazer o seu próprio; senão, herda da categoria.
    simples = a.get("simples") or cat.get("simples", "")
    bloco_simples = (f'<div class="simples"><b>Em português claro:</b> {esc(simples)}</div>'
                     if simples else "")

    # Correção e quem consegue aplicar.
    quem = a.get("quem") or cat.get("quem", "operador")
    correcao = a.get("correcao") or cat.get("correcao", "")
    cls, rotulo = SELO_QUEM.get(quem, SELO_QUEM["operador"])
    bloco_fix = (f'<div class="fix"><span class="selo {cls}">{esc(rotulo)}</span>'
                 f'<span class="fix-txt"><b>Correção:</b> {esc(correcao)}</span></div>'
                 if correcao else "")

    # O número é o apelido do achado: é assim que o operador cita o item na
    # conversa ("me explica o #03") sem ter que copiar título nem fingerprint.
    numero = a.get("numero")
    marca = f'<span class="num">#{numero:02d}</span> ' if isinstance(numero, int) else ""

    classe_pos = " positivo" if e_positivo(a) else ""
    return f"""<div class="item s-{a['severidade']}{classe_pos}" id="item-{numero if numero else a['fingerprint']}">
<p class="tit">{marca}{esc(a['titulo'])}</p>
<div class="tags">{''.join(tags)}</div>
<div class="loc">{esc(a['arquivo'])}:{a['linha']}</div>
<pre>{esc(a['trecho'])}</pre>
{bloco_simples}
<div class="exp">{esc(a['explicacao'])}</div>
{bloco_fix}
<div class="conf"><b>Como confirmar:</b> {esc(a['como_confirmar'])}</div>{nota}
</div>"""


def e_positivo(a: dict) -> bool:
    """Registro de 'olhei e está certo', não item a corrigir.

    O relatório precisa distinguir três coisas: o que quebrou, o que foi
    conferido e está são, e o que ninguém olhou. Sem a segunda, o operador não
    consegue separar "não há falha aqui" de "aqui não foi auditado" — e um
    positivo que some numa execução futura é sinal de regressão.

    Marque com tipo="positivo"; o prefixo no título é aceito como atalho.
    """
    return a.get("tipo") == "positivo" or a.get("titulo", "").upper().startswith("POSITIVO")


def render_legenda(cats_presentes: list) -> str:
    """Tabela fixa com TODAS as categorias — a sigla sozinha não diz nada a ninguém."""
    linhas = []
    for c, d in CATEGORIAS.items():
        presente = c in cats_presentes
        marca = ('<span class="pt-sim">com achado</span>' if presente
                 else '<span class="pt-nao">limpo</span>')
        linhas.append(
            f'<tr class="{"leg-on" if presente else ""}">'
            f'<td class="leg-c">{c}</td>'
            f'<td class="leg-n">{esc(d["nome"])}</td>'
            f'<td>{esc(d["simples"])}</td>'
            f'<td class="leg-m">{marca}</td></tr>')
    return f"""<details class="legenda" open>
<summary>O que significa cada categoria (C1 a C9)</summary>
<table class="tab-leg"><thead><tr>
<th>Sigla</th><th>Categoria</th><th>O que é, em uma frase</th><th>Nesta execução</th>
</tr></thead><tbody>{''.join(linhas)}</tbody></table>
<p class="leg-rod">"Limpo" quer dizer que nada foi encontrado nessa categoria —
não que ela tenha sido esgotada. A aba <b>Cobertura</b> diz o que ficou de fora da varredura.</p>
</details>"""


def render_html(ctx: dict) -> str:
    achados = ctx["achados"]
    suprimidos = ctx["suprimidos"]

    # Numeração única e contínua, atribuída UMA vez na ordem final (severidade →
    # categoria → arquivo). Os painéis por categoria só filtram esta lista, então
    # o #07 é o mesmo item na aba "Todos" e na aba da categoria dele. Os riscos
    # aceitos continuam a mesma sequência — número repetido tornaria a citação
    # ambígua, que é justamente o que a numeração existe para evitar.
    positivos = [a for a in achados if e_positivo(a)]
    achados = [a for a in achados if not e_positivo(a)]

    for i, a in enumerate(achados, start=1):
        a["numero"] = i
    for j, a in enumerate(positivos, start=len(achados) + 1):
        a["numero"] = j
    for k, a in enumerate(suprimidos, start=len(achados) + len(positivos) + 1):
        a["numero"] = k
    contagem = {sev: len([a for a in achados if a["severidade"] == sev and not e_positivo(a)])
                for sev in SEVS}

    placar = "".join(
        f'<div class="card"><div class="n {sev}">{contagem[sev]}</div>'
        f'<div class="l">nota {NOTAS[sev]["nota"]} · {esc(NOTAS[sev]["rotulo"])}</div></div>'
        for sev in SEVS
    )

    d = ctx["diff"]
    if d["primeira_execucao"]:
        bloco_diff = ('<div class="diff"><div class="card" style="grid-column:1/-1">'
                      '<div class="l">Esta é a primeira execução — não há com o que comparar. '
                      'Ela vira a linha de base; a próxima mostrará novos, persistentes e resolvidos.</div></div></div>')
    else:
        card_conhecidos = ((f'<div class="card persist"><div class="n" style="color:#79c0ff">{d["conhecidos"]}</div>'
                            f'<div class="l">Conhecidos (já triados)</div></div>')
                           if d.get("conhecidos") else '')
        bloco_diff = (f'<div class="diff">'
                      f'<div class="card novo"><div class="n critico">{d["novos"]}</div><div class="l">Novos</div></div>'
                      f'<div class="card persist"><div class="n medio">{d["persistentes"]}</div><div class="l">Persistentes</div></div>'
                      f'{card_conhecidos}'
                      f'<div class="card resolv"><div class="n" style="color:#3fb950">{d["resolvidos"]}</div><div class="l">Resolvidos</div></div>'
                      f'</div>')

    cats_presentes = [c for c in CATEGORIAS if any(a["categoria"] == c for a in achados)]
    tabs = ['<div class="tab on" data-alvo="p-todos">Todos ({})</div>'.format(len(achados))]
    paineis = ['<div class="painel on" id="p-todos">'
               + ("".join(render_item(a) for a in achados) or '<div class="vazio">Nenhum achado nesta execução.</div>')
               + "</div>"]
    for c in cats_presentes:
        itens = [a for a in achados if a["categoria"] == c]
        tabs.append(f'<div class="tab" data-alvo="p-{c}">{c} · {esc(cat_nome(c))} ({len(itens)})</div>')
        paineis.append(f'<div class="painel" id="p-{c}">' + "".join(render_item(a) for a in itens) + "</div>")

    linhas_nota = "".join(
        f'<tr><td class="leg-c"><span class="nota-sel n{d["nota"]}">{d["nota"]}</span></td>'
        f'<td class="leg-n">{esc(d["rotulo"])}</td><td>{esc(d["desc"])}</td>'
        f'<td class="leg-m">{contagem[sev]} nesta execução</td></tr>'
        for sev, d in sorted(NOTAS.items(), key=lambda kv: -kv[1]["nota"]))
    legenda_notas = f"""<details class="legenda" open>
<summary>O que significa a nota de risco (1 a 5)</summary>
<table class="tab-leg"><thead><tr>
<th>Nota</th><th>Nível</th><th>O que quer dizer</th><th>Nesta execução</th>
</tr></thead><tbody>{linhas_nota}</tbody></table>
<p class="leg-rod">A nota é dada por <b>quem consegue explorar</b> a falha, não por quanto ela
parece grave. Na dúvida entre duas notas, vale a menor — e o achado diz o que falta para
confirmar. Os itens da aba "Verificado e OK" não entram nesta contagem.</p>
</details>"""

    if positivos:
        tabs.append(f'<div class="tab tab-ok" data-alvo="p-ok">✓ Verificado e OK ({len(positivos)})</div>')
        paineis.append(
            '<div class="painel" id="p-ok">'
            '<div class="nota-ok">Nada aqui pede ação. São pontos que foram conferidos nesta '
            'execução e estavam corretos — ficam registrados para a próxima auditoria comparar: '
            'se um deles sumir da lista, alguma coisa regrediu.</div>'
            + "".join(render_item(a) for a in positivos) + "</div>")

    cob = ctx["cobertura"]
    linhas_cob = [
        ("Modo executado", ctx["modo"]),
        ("Stacks detectadas", ", ".join(ctx["recon"]["stacks"]) or "nenhuma reconhecida"),
        ("Referências consultadas", ", ".join(ctx["recon"]["referencias"])),
        ("Arquivos encontrados", cob["total_encontrados"]),
        ("Arquivos varridos", cob["varridos"]),
        ("Arquivos fora da varredura", cob["cortados"]),
    ]
    if cob.get("motivo_corte"):
        linhas_cob.append(("Motivo do corte", cob["motivo_corte"]))
    for lim in ctx.get("limitacoes", []):
        linhas_cob.append(("Não avaliado", lim))
    tabela_cob = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in linhas_cob)
    tabs.append('<div class="tab" data-alvo="p-cob">Cobertura</div>')
    paineis.append(f'<div class="painel" id="p-cob"><table>{tabela_cob}</table></div>')

    if suprimidos:
        itens_sup = "".join(
            f'<div class="item s-informativo"><p class="tit"><span class="num">#{a.get("numero", 0):02d}</span> {esc(a["titulo"])}</p>'
            f'<div class="loc">{esc(a["arquivo"])}:{a["linha"]} · fp {esc(a["fingerprint"])}</div>'
            f'<div class="conf"><b>Justificativa registrada:</b> {esc(a.get("justificativa", ""))}</div></div>'
            for a in suprimidos)
        tabs.append(f'<div class="tab" data-alvo="p-sup">Riscos aceitos ({len(suprimidos)})</div>')
        paineis.append(f'<div class="painel" id="p-sup">{itens_sup}</div>')

    u = ctx.get("uso", {}) or {}
    if u.get("disponivel"):
        uso_txt = (f'<b>Modelo:</b> {esc(u.get("modelo", "?"))} &nbsp;·&nbsp; '
                   f'<b>Tokens de entrada:</b> {u.get("input_tokens", 0):,} &nbsp;·&nbsp; '
                   f'<b>Saída:</b> {u.get("output_tokens", 0):,} &nbsp;·&nbsp; '
                   f'<b>Cache:</b> {u.get("cache_read_tokens", 0):,}').replace(",", ".")
    else:
        uso_txt = f'<b>Consumo da sessão:</b> indisponível ({esc(u.get("motivo", "formato não reconhecido"))})'

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ll-sec — {esc(ctx['projeto'])}</title><style>{CSS}</style></head><body><div class="wrap">
<h1>Auditoria de segurança — {esc(ctx['projeto'])}</h1>
<div class="sub">{esc(ctx['gerado_em'])} · modo <b>{esc(ctx['modo'])}</b> · somente leitura, nenhum código alterado</div>
<div class="aviso"><b>Este arquivo é um mapa de vulnerabilidades.</b> Não commite, não anexe em
ticket público e não mande por canal inseguro. A pasta de relatórios foi mantida fora do Git.</div>
<div class="meta">{uso_txt}</div>
{bloco_diff}
<div class="placar">{placar}</div>
{legenda_notas}\n{render_legenda(cats_presentes)}
<div class="tabs">{''.join(tabs)}</div>
{''.join(paineis)}
<div class="rodape">
Gerado por <b>ll-sec</b> · Achados marcados como <i>informativo</i> são suspeitas não confirmadas —
cada um diz o que falta para confirmar. Nenhum achado foi corrigido automaticamente.<br>
O bloco de consumo cobre a sessão inteira do Claude Code até o momento da leitura e
<b>não inclui a geração deste relatório</b>; para medir só esta auditoria, rode-a numa sessão nova.
</div>
</div><script>{JS}</script></body></html>"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_recon(args):
    root = Path(args.root).resolve()
    print(json.dumps(detectar_stacks(root), ensure_ascii=False, indent=2))


def cmd_scan(args):
    root = Path(args.root).resolve()
    out = Path(args.out) if os.path.isabs(args.out) else root / args.out
    out.mkdir(parents=True, exist_ok=True)

    recon = detectar_stacks(root)
    arquivos, cobertura = listar_arquivos(root, args.mode, args.since)
    achados = varrer(root, arquivos, recon["stacks"])

    sup = carregar_supressoes(root)
    suprimidos = []
    restantes = []
    for a in achados:
        if a["fingerprint"] in sup:
            a["justificativa"] = sup[a["fingerprint"]]
            suprimidos.append(a)
        else:
            restantes.append(a)

    # Triagem persistente: decisão de triagem gravada pelo render de execuções
    # anteriores (triagem.json). Achado bruto já triado chega pré-classificado
    # com estado "conhecido" — não vira "novo" no diff nem exige re-triagem,
    # a menos que o agente decida revê-lo. Para forçar re-triagem de um item,
    # apague a entrada dele no triagem.json.
    caminho_triagem = out / "triagem.json"
    triagem = {}
    if caminho_triagem.exists():
        try:
            triagem = json.loads(caminho_triagem.read_text(encoding="utf-8"))
        except Exception:
            triagem = {}
    for a in restantes:
        t = triagem.get(a["fingerprint"])
        if not t:
            continue
        for k in ("severidade", "tipo", "titulo", "simples", "correcao", "quem", "nota"):
            if t.get(k):
                a[k] = t[k]
        a["estado"] = "conhecido"
        a["triado_em"] = t.get("data", "")

    # Fingerprints da execução anterior, guardados no payload para o render
    # decidir novo/persistente sobre a lista FINAL (pós-triagem do agente).
    caminho_estado = out / "estado.json"
    try:
        anteriores = json.loads(caminho_estado.read_text(encoding="utf-8")).get("fingerprints", [])
    except Exception:
        anteriores = []

    diff = aplicar_diff(restantes, caminho_estado)
    gitignore = garantir_gitignore(root, out.name if not os.path.isabs(args.out) else args.out)

    payload = dict(
        projeto=root.name, root=str(root), modo=args.mode,
        gerado_em=datetime.now().strftime("%d/%m/%Y %H:%M"),
        recon=recon, cobertura=cobertura, achados=restantes,
        suprimidos=suprimidos, diff=diff, gitignore=gitignore,
        limitacoes=[], uso={}, estado_anterior=anteriores,
    )
    destino = out / "findings.json"
    destino.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # O estado NÃO é gravado aqui de propósito: quem fecha a execução é o render,
    # que conhece a lista final depois da triagem. Gravar os achados crus faria a
    # próxima execução comparar contra ruído que nunca chegou ao relatório.

    resumo = {s: len([a for a in restantes if a["severidade"] == s]) for s in SEVS}
    print(json.dumps({"findings_json": str(destino), "total": len(restantes),
                      "por_severidade": resumo, "suprimidos": len(suprimidos),
                      "diff": diff, "recon": recon, "cobertura": cobertura,
                      "gitignore": gitignore}, ensure_ascii=False, indent=2))


def cmd_render(args):
    dados = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    out = Path(args.out) if os.path.isabs(args.out) else Path(dados["root"]) / args.out
    out.mkdir(parents=True, exist_ok=True)

    if args.uso and Path(args.uso).exists():
        try:
            dados["uso"] = json.loads(Path(args.uso).read_text(encoding="utf-8"))
        except Exception:
            dados["uso"] = {"disponivel": False, "motivo": "JSON de consumo ilegível"}

    # novo x persistente é decidido AQUI, sobre a lista final — não sobre os
    # achados crus do scan. O agente acrescenta e remove itens na triagem, e um
    # achado que ele reescreveu mas que já existia na execução anterior não pode
    # aparecer como novidade: "10 novos" quando nada mudou destrói a confiança
    # no bloco de diff, que é a parte do relatório que o operador lê primeiro.
    anteriores = set(dados.get("estado_anterior") or [])
    if anteriores:
        for a in dados["achados"] + dados.get("suprimidos", []):
            if a.get("estado") == "conhecido":
                continue
            a["estado"] = "persistente" if a["fingerprint"] in anteriores else "novo"

        atuais = {a["fingerprint"] for a in dados["achados"]}
        resolvidos = sorted(anteriores - atuais)
        dados["diff"] = {
            "primeira_execucao": False,
            "novos": len([a for a in dados["achados"] if a["estado"] == "novo"]),
            "persistentes": len([a for a in dados["achados"] if a["estado"] == "persistente"]),
            "conhecidos": len([a for a in dados["achados"] if a["estado"] == "conhecido"]),
            "resolvidos": len(resolvidos),
            "fingerprints_resolvidos": resolvidos,
        }

    modo_label = {"completa": "completo", "rapida": "rapido"}.get(
        dados.get("modo", ""), dados.get("modo", "") or "run")
    proj = re.sub(r"[^A-Za-z0-9_-]+", "-", dados.get("projeto", "projeto")).strip("-") or "projeto"
    nome = f"ll-sec-{proj}-{modo_label}-{datetime.now().strftime('%Y-%m-%d-%H%M')}.html"
    destino = out / nome
    destino.write_text(render_html(dados), encoding="utf-8")

    # Memória de triagem: cada achado da lista final grava sua classificação por
    # fingerprint. Na próxima varredura o scan pré-aplica isso e marca o item
    # como "conhecido" — o diff para de acusar novidade no que já foi triado.
    tri_path = out / "triagem.json"
    try:
        tri = json.loads(tri_path.read_text(encoding="utf-8"))
    except Exception:
        tri = {}
    for a in dados["achados"]:
        ent = {k: a.get(k) for k in ("severidade", "tipo", "titulo", "simples",
                                     "correcao", "quem", "nota") if a.get(k)}
        ent["regra"] = a.get("regra", "")
        ent["arquivo"] = a.get("arquivo", "")
        ent["data"] = a.get("triado_em") or dados.get("gerado_em", "")
        tri[a["fingerprint"]] = ent
    tri_path.write_text(json.dumps(tri, ensure_ascii=False, indent=1), encoding="utf-8")

    # Fecha a execução: o estado passa a ser a lista que o operador de fato viu.
    (out / "estado.json").write_text(json.dumps(
        {"data": dados.get("gerado_em", ""), "modo": dados.get("modo", ""),
         "fingerprints": [a["fingerprint"] for a in dados["achados"]]},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"html": str(destino), "achados": len(dados["achados"])},
                     ensure_ascii=False, indent=2))


def main():
    ap = argparse.ArgumentParser(description="ll-sec — varredura de segurança somente-leitura")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("recon"); p.add_argument("--root", default="."); p.set_defaults(f=cmd_recon)

    p = sub.add_parser("scan")
    p.add_argument("--root", default=".")
    p.add_argument("--mode", choices=["rapida", "completa", "diff"], default="rapida")
    p.add_argument("--out", default="./ll-sec-relatorios")
    p.add_argument("--since", default=None, help="commit de referência para o modo diff")
    p.set_defaults(f=cmd_scan)

    p = sub.add_parser("render")
    p.add_argument("--root", default=".")
    p.add_argument("--out", default="./ll-sec-relatorios")
    p.add_argument("--findings", required=True)
    p.add_argument("--uso", default=None, help="JSON do session_usage.py")
    p.set_defaults(f=cmd_render)

    args = ap.parse_args()
    args.f(args)


if __name__ == "__main__":
    sys.exit(main())
