#!/usr/bin/env python3
"""
ll-sec — varredura de segurança somente-leitura, portável entre projetos.

Faz o trabalho mecânico e determinístico da auditoria: reconhecimento de stack,
varredura por padrões, entropia, fingerprint, diff contra a execução anterior,
supressões e renderização do HTML. O julgamento fica com o agente, que lê o
JSON produzido aqui, confirma/descarta os achados lendo os arquivos e pode
acrescentar achados próprios antes de renderizar.

Só lê o repositório auditado: ZERO escrita dentro dele. Tudo o que a skill
grava — findings.json, relatório HTML, estado, triagem — mora fora do alvo, em
~/.local/state/ll-sec/<repo-id>/ (0700, arquivos 0600). Estado que influencia
decisão não pode ficar do lado de dentro do que está sendo auditado.

Uso:
  ll_sec_scan.py recon  --root .
  ll_sec_scan.py scan   --root . --mode rapida
  ll_sec_scan.py render --root . --findings <f.json>

Saída (exit code):
  0  execução válida, sem achado bloqueante E cobertura requerida completa
  1  erro de execução ou violação de contrato
  2  achado bloqueante (crítico/alto)
  3  auditoria incompleta (cobertura parcial ou nenhuma)
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

LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
             "Gemfile.lock", "poetry.lock", "Cargo.lock", "go.sum", "Pipfile.lock",
             "bun.lockb", "pdm.lock", "uv.lock"}

# Não é lista de "o que ignorar": é lista de "o que contar como binário no
# inventário". A diferença importa — o inventário publica o denominador, e
# arquivo que ninguém conta é arquivo que ninguém sabe que existe.
EXT_BINARIA = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".pyd",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".ogg", ".webm", ".psd", ".ai", ".sketch", ".db", ".sqlite", ".sqlite3",
    ".wasm", ".node", ".pack", ".idx", ".DS_Store",
}

# Diretórios excluídos por política, separados pelo MOTIVO da exclusão: o
# relatório mostra "dependência" e "gerado" em linhas diferentes porque somar
# os dois num total só produz aquele "4% de cobertura" que é tecnicamente
# correto e operacionalmente inútil.
DIRS_DEPENDENCIA = {"node_modules", "vendor", ".venv", "venv", "Pods", ".terraform",
                    "bower_components", "site-packages"}
DIRS_GERADO = {"dist", "build", ".next", "out", "coverage", ".turbo", ".cache",
               "target", "bin", "obj", ".gradle", "__pycache__", ".pytest_cache",
               ".svelte-kit", ".agent-browser", "ll-sec-relatorios"}


class ErroDeExecucao(Exception):
    """Falha que invalida a auditoria inteira. Sai como erro (exit 1), NUNCA
    como relatório: relatório vazio é lido como aprovação, que é o defeito que
    este lote existe para fechar."""

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
                 "limitacoes": [], "nao_lidos": [], "degradacao_global": [],
                 "inventario": {}, "ext_do_projeto": {}, "lidos": []}

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
            arquivos = [p for p in alvos if p.is_file() and relevante(p, root)]
            cobertura["total_encontrados"] = len(arquivos)
            cobertura["varridos"] = len(arquivos)
            cobertura["ref_diff"] = ref
            texto = (f"modo diff: só os {len(arquivos)} arquivos alterados desde `{ref}` foram "
                     "varridos; o resto do repositório não foi olhado nesta execução")
            cobertura["limitacoes"].append(dict(
                tipo="modo_diff", descricao=texto, afeta="todos", itens=[]))
            cobertura["degradacao_global"].append(texto)
            cobertura["ext_do_projeto"] = contar_extensoes(arquivos, root)
            return arquivos, cobertura
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError, OSError) as e:
            detalhe = (getattr(e, "stderr", "") or str(e)).strip().splitlines() or [""]
            motivo = (f"o modo diff foi pedido mas o `git diff {ref}` falhou "
                      f"({detalhe[0][:160]}); a execução caiu para varredura completa")
            cobertura["motivo_corte"] = motivo
            cobertura["limitacoes"].append(dict(
                tipo="modo_diff_indisponivel", descricao=motivo, afeta="todos", itens=[]))
            cobertura["degradacao_global"].append(motivo)
            mode = "rapida"

    inv: dict[str, list[Path]] = {k: [] for k in (
        "analisar", "nao_reconhecido", "acima_do_limite", "ilegivel", "fora_da_raiz")}
    politica: dict[str, int] = {"dependencia": 0, "gerado": 0, "lockfile": 0, "binario": 0}

    # Inventário independente: conta o que EXISTE, sem passar pelo filtro de
    # relevância. Sem isso, "cobertura completa" quer dizer "completa segundo o
    # meu próprio filtro" — a definição circular que deixou .github/, .md e
    # .toml de fora por meses sem ninguém perceber. Contar não é ler: dentro de
    # node_modules o walk só soma len(filenames), sem construir caminho nem
    # abrir arquivo.
    for dirpath, dirnames, filenames in os.walk(root):
        # `d != ".git"`, e não `startswith(".git")`: o prefixo comia `.github/` e
        # `.gitlab/` junto com o `.git/`, e workflow de CI é dos lugares mais
        # comuns para segredo em texto claro. Só o diretório do Git sai — e ele
        # sai inteiro, sem ser inventariado, porque contar objeto de Git não diz
        # nada a ninguém.
        dirnames[:] = [d for d in dirnames if d != ".git"]
        balde = balde_do_diretorio(Path(dirpath), root)
        if balde:
            politica[balde] += len(filenames)
            continue
        for fn in filenames:
            p = Path(dirpath) / fn
            c = classificar(p, root)
            if c in politica:
                politica[c] += 1
            else:
                inv[c].append(p)

    encontrados = inv["analisar"]
    cobertura["total_encontrados"] = len(encontrados)
    cobertura["inventario"] = {k: len(v) for k, v in inv.items()}
    cobertura["inventario"].update(politica)
    cobertura["ext_do_projeto"] = contar_extensoes(
        inv["analisar"] + inv["nao_reconhecido"] + inv["acima_do_limite"]
        + inv["ilegivel"] + inv["fora_da_raiz"], root)

    if not encontrados and not any(inv[k] for k in
                                   ("nao_reconhecido", "acima_do_limite", "ilegivel")):
        # Zero arquivo de código encontrado quase nunca é "projeto limpo": é
        # raiz errada, filtro quebrado ou repositório que não é o que se pensa.
        # Sai como erro, não como relatório verde.
        raise ErroDeExecucao(
            f"nenhum arquivo de código foi encontrado sob {root} "
            f"(inventário: {cobertura['inventario']}). "
            "A raiz está errada, ou tudo ali é dependência/gerado/binário. "
            "Nenhum relatório foi emitido — auditoria sem arquivo não é auditoria limpa.")

    for balde, rotulo in (("nao_reconhecido", "de tipo não reconhecido"),
                          ("acima_do_limite", "acima do limite de tamanho"),
                          ("ilegivel", "sem permissão de leitura"),
                          ("fora_da_raiz", "apontando para fora da raiz")):
        for p_ in inv[balde]:
            cobertura["nao_lidos"].append(dict(arquivo=rel_de(p_, root),
                                               ext=chave_ext(p_), motivo=rotulo))

    if inv["fora_da_raiz"]:
        cobertura["limitacoes"].append(dict(
            tipo="fora_da_raiz",
            descricao=("arquivo apontando para fora da raiz auditada (symlink) — recusado sem ser "
                       "lido, para o conteúdo de fora do repositório não entrar no relatório"),
            afeta="todos",
            itens=[rel_de(p, root) for p in inv["fora_da_raiz"][:40]]))
    if inv["acima_do_limite"]:
        cobertura["limitacoes"].append(dict(
            tipo="acima_do_limite",
            descricao="arquivo de código acima de 800 KB — não foi lido nesta execução",
            afeta="arquivos",
            itens=[rel_de(p, root) for p in inv["acima_do_limite"][:40]]))
    if inv["ilegivel"]:
        cobertura["limitacoes"].append(dict(
            tipo="ilegivel",
            descricao="arquivo de código que o auditor não conseguiu abrir (permissão ou erro de E/S)",
            afeta="arquivos",
            itens=[rel_de(p, root) for p in inv["ilegivel"][:40]]))
    if inv["nao_reconhecido"]:
        cobertura["limitacoes"].append(dict(
            tipo="nao_reconhecido",
            descricao=(f"{len(inv['nao_reconhecido'])} arquivos do projeto têm tipo que o scanner "
                       "não sabe ler e ficaram fora da varredura — este é o número que mostra "
                       "onde está o próximo furo de cobertura"),
            afeta="arquivos",
            itens=[rel_de(p, root) for p in inv["nao_reconhecido"][:40]]))

    encontrados.sort(key=lambda p: (prioridade(p, root), str(p)))

    teto = 1200 if mode == "completa" else 600
    if len(encontrados) > teto:
        cortados = encontrados[teto:]
        cobertura["cortados"] = len(cortados)
        cobertura["motivo_corte"] = (
            f"repositório grande: varridos os {teto} arquivos de maior prioridade "
            f"(rotas/API → auth → banco/migrations → render de input → resto); "
            f"{len(cortados)} arquivos de menor prioridade ficaram de fora"
        )
        cobertura["limitacoes"].append(dict(
            tipo="orcamento",
            descricao=cobertura["motivo_corte"],
            afeta="arquivos",
            itens=[rel_de(p, root) for p in cortados[:40]]))
        cobertura["ext_cortadas"] = contar_extensoes(cortados, root)
        for p_ in cortados:
            cobertura["nao_lidos"].append(dict(arquivo=rel_de(p_, root),
                                               ext=chave_ext(p_),
                                               motivo="fora do orçamento do modo"))
        encontrados = encontrados[:teto]

    cobertura["varridos"] = len(encontrados)
    return encontrados, cobertura


def absorver_diagnostico(cobertura: dict, diag: dict) -> None:
    """O que a varredura descobriu na hora de LER (arquivo que não abriu, link
    para fora) entra na cobertura junto com o que a listagem já sabia."""
    cobertura["lidos"] = diag["lidos"]
    for chave, tipo, texto in (
        ("ilegiveis", "ilegivel",
         "arquivo elegível que não pôde ser lido na varredura (permissão ou erro de E/S)"),
        ("fora_da_raiz", "fora_da_raiz",
         "arquivo apontando para fora da raiz auditada — recusado sem ser lido"),
    ):
        if not diag[chave]:
            continue
        cobertura["inventario"][tipo if tipo != "ilegivel" else "ilegivel"] = (
            cobertura["inventario"].get(tipo, 0) + len(diag[chave]))
        cobertura["limitacoes"].append(dict(
            tipo=tipo, descricao=texto, afeta="arquivos", itens=diag[chave][:40]))
        cobertura["varridos"] = max(0, cobertura.get("varridos", 0) - len(diag[chave]))
        rotulo = "sem permissão de leitura" if tipo == "ilegivel" else "apontando para fora da raiz"
        for rel in diag[chave]:
            cobertura["nao_lidos"].append(dict(arquivo=rel, ext=chave_ext(Path(rel)),
                                               motivo=rotulo))


def balde_do_diretorio(dirpath: Path, root: Path) -> str | None:
    """Este diretório inteiro é exclusão de política? Devolve o balde do
    inventário ou None quando o diretório é código do projeto."""
    try:
        partes = dirpath.relative_to(root).parts
    except ValueError:
        return "gerado"
    for parte in partes:
        if parte in DIRS_DEPENDENCIA:
            return "dependencia"
        if parte in DIRS_GERADO or parte in IGNORAR_DIRS:
            return "gerado"
    return None


def rel_de(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def chave_ext(p: Path) -> str:
    """A chave que decide se um check se aplica a um arquivo: a extensão, ou o
    próprio nome quando o arquivo não tem extensão (.env, Dockerfile).

    `.env.local` conta como `.env`, não como `.local`: quem lê o inventário
    quer saber quantos arquivos de ambiente existem, não quantos sufixos."""
    if p.name.startswith(".env"):
        return ".env"
    return p.suffix.lower() or p.name


def contar_extensoes(arquivos: list[Path], root: Path) -> dict[str, int]:
    contagem: dict[str, int] = {}
    for p in arquivos:
        k = chave_ext(p)
        contagem[k] = contagem.get(k, 0) + 1
    return contagem


def dentro_da_raiz(p: Path, root: Path) -> bool:
    """O arquivo, DEPOIS de resolver links, continua sob a raiz auditada?

    Um `config.txt -> ~/.ssh/id_rsa` dentro do repositório auditado não é um
    buraco de cobertura: é exfiltração da máquina que audita, com o conteúdo
    saindo dentro do relatório. Só symlink paga o custo do resolve() — o walk
    não desce por link de diretório."""
    if not p.is_symlink():
        return True
    try:
        return p.resolve().is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def classificar(p: Path, root: Path) -> str:
    """Por que este arquivo entra, ou não entra, na varredura.

    Devolve o motivo em vez de um booleano porque o inventário (0.1) publica o
    denominador: cada arquivo que fica de fora precisa aparecer contado, com o
    motivo ao lado. "Não varri" sem número é a mesma coisa que silêncio.
    """
    try:
        # relative_to(root), NÃO p.parts: testar o caminho absoluto fazia os
        # ancestrais ACIMA da raiz entrarem no teste, e um repositório que
        # morasse sob uma pasta chamada build/, bin/ ou out/ varria ZERO
        # arquivo e saía com as nove categorias "limpas".
        partes = p.relative_to(root).parts
    except ValueError:
        return "fora_da_raiz"

    for parte in partes[:-1]:
        if parte in DIRS_DEPENDENCIA:
            return "dependencia"
        if parte in DIRS_GERADO or parte == ".git":
            return "gerado"
        if parte in IGNORAR_DIRS:
            return "gerado"
    if p.name in LOCKFILES:
        return "lockfile"
    if not dentro_da_raiz(p, root):
        return "fora_da_raiz"

    if p.name in ARQ_SEM_EXT or p.name.startswith(".env"):
        pass
    elif p.suffix.lower() in EXT_CODIGO:
        pass
    elif p.suffix.lower() in EXT_BINARIA:
        return "binario"
    else:
        return "nao_reconhecido"

    try:
        if p.stat().st_size > 800_000:
            return "acima_do_limite"
    except OSError:
        return "ilegivel"
    return "analisar"


def relevante(p: Path, root: Path) -> bool:
    return classificar(p, root) == "analisar"


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
         mascarar=False,
         rx=R(r"allow\s+(read|write|create|update|delete|read,\s*write)[^;]*:\s*if\s+true"),
         ext={".rules"},
         explica="A regra libera a operação sem nenhuma condição. Qualquer pessoa com o "
                 "endereço do projeto lê ou escreve o banco inteiro, sem login.",
         confirma="Abrir o arquivo de regras e verificar se essa cláusula está em produção."),
    dict(id="C1-firestore-so-logado", cat="C1", sev="alto",
         titulo="Regra exige apenas estar logado, sem checar dono do dado",
         mascarar=False,
         rx=R(r"allow\s+(read|write|create|update|delete|read,\s*write)[^;]*:\s*if\s+request\.auth\s*!=\s*null\s*;"),
         ext={".rules"},
         explica="Qualquer usuário autenticado — inclusive um recém-cadastrado — alcança "
                 "os dados de todos os outros. Falta comparar o dono do documento.",
         confirma="Verificar se a coleção guarda dado de um usuário específico."),
    dict(id="C1-rls-desligada", cat="C1", sev="critico",
         titulo="Row Level Security desativada explicitamente",
         mascarar=False,
         rx=R(r"alter\s+table\s+[^\s;]+\s+disable\s+row\s+level\s+security"),
         ext={".sql"},
         explica="Desligar RLS no Postgres do Supabase expõe a tabela inteira à chave "
                 "pública (anon), que roda no navegador do usuário.",
         confirma="Conferir se a tabela é alcançável pela API pública."),
    dict(id="C1-policy-permissiva", cat="C1", sev="alto",
         titulo="Policy de RLS com condição sempre verdadeira",
         mascarar=False,
         rx=R(r"create\s+policy[\s\S]{0,200}?using\s*\(\s*true\s*\)"),
         ext={".sql"},
         explica="A policy existe mas não filtra nada: `using (true)` autoriza toda linha "
                 "para todo mundo. É RLS ligada com a porta escancarada.",
         confirma="Ver se a tabela contém dado de mais de um usuário/tenant."),
    dict(id="C1-grant-public", cat="C1", sev="alto",
         titulo="Permissão ampla concedida a PUBLIC",
         mascarar=False,
         rx=R(r"grant\s+(all|select|insert|update|delete)[^;]{0,80}\bto\s+public\b"),
         ext={".sql"},
         explica="`TO PUBLIC` alcança qualquer papel do banco, inclusive o anônimo.",
         confirma="Checar quais papéis a aplicação expõe."),
    dict(id="C1-service-role-no-cliente", cat="C1", sev="critico",
         titulo="Chave de serviço (service_role) usada em código de cliente",
         rx=R(r"(service_role|SUPABASE_SERVICE_ROLE|serviceRoleKey|FIREBASE_ADMIN)"),
         # É o segredo mais perigoso que a ferramenta sabe achar e era o único
         # que saía cru no HTML: a mesma linha casava também o C4-jwt-literal,
         # que saía mascarado, então a assinatura do JWT aparecia duas vezes.
         mascarar=True,
         ext={".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"},
         caminho_exige=R(r"(client|components?|pages?|app|public|frontend|src)"),
         caminho_nao=R(r"(server|api|route\.|actions?|lib/server|\.server\.)"),
         explica="A chave de serviço ignora RLS e toda regra de autorização. Se ela chega "
                 "ao navegador, o banco inteiro fica aberto para quem abrir o DevTools.",
         confirma="Confirmar se o arquivo roda mesmo no cliente (tem 'use client'? é bundle?)."),

    # ---------------- C2 — autorização no front-end ----------------
    dict(id="C2-role-no-storage", cat="C2", sev="alto",
         titulo="Papel/permissão lido de localStorage ou sessionStorage",
         mascarar=False,
         rx=R(r"(localStorage|sessionStorage)\.(getItem\(\s*['\"][^'\"]*(admin|role|perm|is_?admin|nivel)|[a-z_]*\b(isAdmin|role))"),
         explica="O usuário edita localStorage em dois cliques. Se a permissão vem dali, "
                 "virar admin é digitar uma linha no console.",
         confirma="Ver se o servidor revalida esse papel antes de liberar a ação."),
    dict(id="C2-guard-so-visual", cat="C2", sev="medio",
         titulo="Permissão decidida no componente, possivelmente sem checagem no servidor",
         mascarar=False,
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
         mascarar=False,
         rx=R(r"(findUnique|findFirst|findOne|findById|get\()\s*\(?\s*\{?[^)}]{0,120}(id\s*:\s*(req\.|request\.|params\.|ctx\.params|searchParams))"),
         explica="O identificador vem do cliente e vira consulta direta. Trocar o número na "
                 "URL devolve o dado de outra pessoa (IDOR).",
         confirma="Verificar se a consulta também filtra por usuário/tenant da sessão."),
    dict(id="C3-idor-sql-por-id", cat="C3", sev="alto",
         titulo="SQL filtrando só por id vindo da requisição",
         mascarar=False,
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
         # `.env`, docker-compose, YAML de CI, manifesto k8s e `export VAR=valor`
         # NÃO usam aspas — e são exatamente onde segredo mora. Exigir aspas
         # fazia o mesmo valor sair ALTO num .ts e ZERO num .env.
         # `[ \t]` e não `\s` em toda a regra: sem aspas delimitando o valor,
         # um `\s*` atravessa a quebra de linha e casa o NOME de uma linha com o
         # VALOR da seguinte — achado com número de linha errado.
         rx_sem_aspas=R(r"(?:export[ \t]+|const|let|var|final|val)?[ \t]*\b\w*(secret|password|passwd|senha|api_?key|apikey|token|auth)\w*[ \t]*[:=][ \t]*['\"]?([^'\"\s]{12,})['\"]?"),
         mascarar=True,
         ignora_valor=R(r"^(process\.env|import\.meta|os\.environ|env\.|<|\{\{|\$\{|xxx|todo|change|your|exemplo|example|placeholder|dummy|fake|test|redacted|\*+)"),
         explica="Valor fixo em variável com nome de segredo. Mesmo que hoje seja de teste, "
                 "o padrão é o que vaza credencial real amanhã.",
         confirma="Checar se o valor é usado contra um serviço real."),

    # ---------------- C5 — input sem sanitização / XSS ----------------
    dict(id="C5-innerhtml", cat="C5", sev="medio",
         titulo="HTML montado a partir de valor dinâmico",
         mascarar=False,
         rx=R(r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\()"),
         explica="Se o valor vier do usuário, o navegador executa o script que ele mandar "
                 "(XSS) — sequestro de sessão, ação em nome da vítima.",
         confirma="Rastrear a origem do valor: veio de input, URL, banco ou é constante?"),
    dict(id="C5-dangerously", cat="C5", sev="medio",
         titulo="dangerouslySetInnerHTML / v-html com valor dinâmico",
         mascarar=False,
         rx=R(r"(dangerouslySetInnerHTML|v-html\s*=)"),
         explica="A API existe para casos em que o HTML é confiável. Com valor de usuário, é XSS.",
         confirma="Ver se o conteúdo passa por sanitizador (DOMPurify, sanitize-html)."),
    dict(id="C5-eval", cat="C5", sev="alto",
         titulo="Execução dinâmica de código",
         mascarar=False,
         rx=R(r"(\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*[`'\"]?\s*\$\{|setTimeout\s*\(\s*['\"])"),
         explica="Executar string como código transforma qualquer input em execução remota.",
         confirma="Verificar se a string tem qualquer parte controlada pelo usuário."),
    dict(id="C5-sql-concatenado", cat="C5", sev="critico",
         titulo="SQL montado por concatenação ou interpolação",
         mascarar=False,
         rx=R(r"(query|execute|raw|prepare)\s*\(\s*[`'\"](?:[^`'\"]*?)(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,120}?(\+\s*\w|\$\{|%\s*\(|\bf['\"])"),
         explica="Injeção de SQL: o usuário passa a escrever parte da consulta. Dá para ler "
                 "tabela inteira, autenticar-se como outro ou apagar dados.",
         confirma="Confirmar que o trecho interpolado vem do usuário e trocar por parâmetro."),
    dict(id="C5-comando-shell", cat="C5", sev="critico",
         titulo="Comando de sistema montado com valor dinâmico",
         mascarar=False,
         rx=R(r"(child_process\.)?(exec|execSync|spawnSync)\s*\(\s*[`'\"][^`'\"]*\$\{|os\.system\s*\(\s*f['\"]|subprocess\.\w+\([^)]*shell\s*=\s*True"),
         explica="Injeção de comando: o usuário emenda `; rm -rf` e o servidor obedece.",
         confirma="Ver a origem da variável e trocar por execução com lista de argumentos."),

    # ---------------- C6 — autenticação e sessão ----------------
    dict(id="C6-jwt-sem-verificacao", cat="C6", sev="critico",
         titulo="JWT decodificado sem verificar assinatura",
         mascarar=False,
         rx=R(r"(jwt\.decode\s*\(|jwtDecode\s*\(|decodeJwt\s*\(|verify\s*:\s*false|verify_signature['\"]?\s*:\s*False)"),
         explica="Decodificar não é validar. Sem conferir a assinatura, qualquer pessoa forja "
                 "um token dizendo que é admin.",
         confirma="Ver se existe um `verify` com a chave em algum ponto do fluxo."),
    dict(id="C6-alg-none", cat="C6", sev="critico",
         titulo="Algoritmo 'none' aceito na validação de token",
         mascarar=False,
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
         mascarar=False,
         rx=R(r"(res\.cookie|cookies\(\)\.set|setCookie|document\.cookie\s*=)"),
         explica="Sem `httpOnly` um XSS lê a sessão; sem `secure` ela trafega em claro; sem "
                 "`sameSite` fica exposta a CSRF.",
         confirma="Ler as opções passadas na chamada e confirmar as três flags."),

    # ---------------- C7 — CSRF, CORS, headers, redirect, SSRF ----------------
    dict(id="C7-cors-aberto", cat="C7", sev="alto",
         titulo="CORS liberado para qualquer origem",
         mascarar=False,
         rx=R(r"(origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|cors\(\s*\)|origin\s*:\s*true)"),
         explica="Origem `*` combinada com credenciais deixa qualquer site chamar a API "
                 "com o cookie da vítima.",
         confirma="Verificar se `credentials: true` está junto — aí a severidade sobe."),
    dict(id="C7-cors-refletido", cat="C7", sev="alto",
         titulo="Origem do requisitante refletida sem allowlist",
         mascarar=False,
         rx=R(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*(req|request)\.(headers)?[\.\[]"),
         explica="Refletir o `Origin` recebido equivale a liberar todo mundo, só que "
                 "passando pela checagem do navegador.",
         confirma="Conferir se há lista de origens permitidas antes da reflexão."),
    dict(id="C7-open-redirect", cat="C7", sev="medio",
         titulo="Redirecionamento para destino controlado pelo usuário",
         mascarar=False,
         rx=R(r"(redirect|location)\s*\(?\s*=?\s*(req|request)\.(query|params|body)"),
         explica="Open redirect: o atacante manda um link do seu domínio que joga a vítima "
                 "no site dele. Base clássica de phishing.",
         confirma="Verificar se o destino é validado contra uma allowlist."),
    dict(id="C7-ssrf", cat="C7", sev="alto",
         titulo="Requisição do servidor para URL vinda do usuário (SSRF)",
         mascarar=False,
         rx=R(r"(fetch|axios\.(get|post)|requests\.(get|post)|urlopen|HttpClient)\s*\(\s*(req|request)\.(query|body|params)"),
         explica="O servidor busca a URL que o usuário mandar — inclusive endereços internos "
                 "e metadados de nuvem (169.254.169.254).",
         confirma="Ver se há validação de esquema e host antes da chamada."),
    dict(id="C7-mutacao-por-get", cat="C7", sev="medio",
         titulo="Operação que altera estado exposta em GET",
         mascarar=False,
         rx=R(r"\.get\s*\(\s*['\"][^'\"]*(delete|remove|create|update|add|set|reset|drop)[^'\"]*['\"]"),
         explica="Mudar estado por GET é acionável por uma tag de imagem em outro site (CSRF), "
                 "e ainda pode ser disparado por pré-carregamento do navegador.",
         confirma="Confirmar que o handler realmente escreve."),

    # ---------------- C9 — tentativa de manipular a auditoria ----------------
    dict(id="C9-prompt-injection", cat="C9", sev="alto",
         titulo="Texto no repositório tentando direcionar a análise da IA",
         mascarar=False,
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
# Catálogo de checks — cobertura de CAPACIDADE
# --------------------------------------------------------------------------
# Cobertura tem dois andares, e confundi-los é o que deixa a categoria mentir
# com sintaxe nova:
#
#   operacional — os checks declarados de fato rodaram sobre os arquivos elegíveis?
#   capacidade  — quais checks a categoria SE PROPÕE a ter, e o que ficou de fora?
#
# Sem o segundo andar, uma C5 com `sql_injection` e `xss` completos sai
# "cobertura: completa" enquanto `command_injection` e `template_injection`
# nunca foram implementados. Por isso `known_gaps` é declarado, não implícito:
# `completa` passa a significar exatamente "execução completa da capacidade
# declarada" — nunca "provamos que não há injeção".
#
# E o efeito imediato de honestidade: a C8 nasce aqui com `checks: []`. A
# categoria vazia deixa de conseguir se esconder atrás de um enum.

CATALOGO = {
    "C1": dict(capability_version=1, checks=[
        dict(id="firebase_rules", titulo="Regras do Firestore/Storage",
             regras=("C1-firestore-aberto", "C1-firestore-so-logado")),
        dict(id="postgres_rls", titulo="RLS, policies e grants do Postgres",
             regras=("C1-rls-desligada", "C1-policy-permissiva", "C1-grant-public")),
        dict(id="chave_de_servico_no_cliente", titulo="Chave de serviço em código de cliente",
             regras=("C1-service-role-no-cliente",)),
    ], known_gaps=[
        "autorização em backend próprio, sem RLS (não há check)",
        "policy com predicado fraco mas não trivial — só `using (true)` é detectado",
        "regras de Storage e de Realtime",
        "confronto entre a rota e a tabela que ela alcança (exige fluxo, não padrão)",
    ]),
    "C2": dict(capability_version=1, checks=[
        dict(id="papel_no_armazenamento_local", titulo="Papel lido de localStorage/sessionStorage",
             regras=("C2-role-no-storage",)),
        dict(id="guarda_visual", titulo="Permissão decidida no componente",
             regras=("C2-guard-so-visual",)),
    ], known_gaps=[
        "confirmar se o endpoint correspondente revalida o papel (exige o par tela↔rota)",
        "middleware de autorização ausente em rota nova",
        "papel vindo de cookie ou de query string",
    ]),
    "C3": dict(capability_version=1, checks=[
        dict(id="consulta_por_id_do_cliente", titulo="ORM consultando por id da requisição",
             regras=("C3-idor-consulta-por-id",)),
        dict(id="sql_por_id_do_cliente", titulo="SQL filtrando só por id da requisição",
             regras=("C3-idor-sql-por-id",)),
    ], known_gaps=[
        "IDOR só se confirma em runtime: identidade da sessão × dado devolvido",
        "id em rota REST sem ORM reconhecido",
        "escopo por tenant aplicado em camada acima (não é visível por padrão)",
    ]),
    "C4": dict(capability_version=1, checks=[
        dict(id="prefixo_de_chave_conhecido", titulo="Chave de API com prefixo reconhecido",
             regras=("C4-chave-conhecida",)),
        dict(id="chave_privada", titulo="Chave privada embutida",
             regras=("C4-chave-privada",)),
        dict(id="url_com_credencial", titulo="String de conexão com senha",
             regras=("C4-url-com-senha",)),
        dict(id="jwt_literal", titulo="JWT literal no código",
             regras=("C4-jwt-literal",)),
        dict(id="segredo_atribuido", titulo="Segredo atribuído a variável",
             regras=("C4-segredo-atribuido",)),
        dict(id="entropia", titulo="String de alta entropia em nome de segredo",
             regras=("C4-entropia",), exts=None),
        dict(id="permissao_do_arquivo_de_segredo", titulo="Modo do arquivo .env/.pem/.key",
             regras=("C4-permissao-arquivo-segredo",), escopo="raiz"),
        dict(id="arquivo_de_segredo_ilegivel", titulo="Arquivo de segredo que não pôde ser aberto",
             regras=("C4-arquivo-ilegivel",), escopo="raiz"),
    ], known_gaps=[
        "histórico do Git não é varrido (gitleaks não roda no modo padrão)",
        "prefixos de 2026 ausentes da lista: sk-ant-, sk-proj-, sbp_, hf_, whsec_, npm_, ASIA",
        "segredo em binário, base64 ou dentro de imagem",
        "segredo em variável de ambiente do runtime (fora do repositório)",
    ]),
    "C5": dict(capability_version=1, checks=[
        dict(id="html_dinamico", titulo="HTML montado com valor dinâmico",
             regras=("C5-innerhtml", "C5-dangerously")),
        dict(id="execucao_dinamica", titulo="Execução dinâmica de código",
             regras=("C5-eval",)),
        dict(id="sql_concatenado", titulo="SQL montado por concatenação",
             regras=("C5-sql-concatenado",)),
        dict(id="comando_de_shell", titulo="Comando de sistema com valor dinâmico",
             regras=("C5-comando-shell",)),
    ], known_gaps=[
        "taint entre arquivos: a origem do valor não é rastreada",
        "template injection (Jinja, EJS, Handlebars)",
        "deserialização insegura (pickle, yaml.load, unserialize)",
        "path traversal e upload sem validação",
        "XSS via atributo (href/src) e via framework fora de React/Vue",
    ]),
    "C6": dict(capability_version=1, checks=[
        dict(id="jwt_sem_verificacao", titulo="Token decodificado sem verificar assinatura",
             regras=("C6-jwt-sem-verificacao", "C6-alg-none")),
        dict(id="segredo_de_assinatura_fixo", titulo="Segredo de assinatura embutido",
             regras=("C6-jwt-segredo-fixo",)),
        dict(id="flags_de_cookie", titulo="Cookie de sessão sem httpOnly/secure/sameSite",
             regras=("C6-cookie-inseguro",)),
    ], known_gaps=[
        "as opções reais do cookie não são lidas — o check só vê a chamada",
        "política de senha, fluxo de reset e enumeração de usuário",
        "expiração, rotação e revogação de sessão",
        "MFA e proteção contra força bruta",
    ]),
    "C7": dict(capability_version=1, checks=[
        dict(id="cors", titulo="CORS aberto ou refletido",
             regras=("C7-cors-aberto", "C7-cors-refletido")),
        dict(id="redirecionamento_aberto", titulo="Redirect para destino do usuário",
             regras=("C7-open-redirect",)),
        dict(id="ssrf", titulo="Requisição do servidor para URL do usuário",
             regras=("C7-ssrf",)),
        dict(id="mutacao_por_get", titulo="Operação que altera estado exposta em GET",
             regras=("C7-mutacao-por-get",)),
    ], known_gaps=[
        "token anti-CSRF: a ausência não é detectada, só a mutação por GET",
        "cabeçalhos de segurança (CSP, HSTS, X-Frame-Options) não são verificados",
        "CORS configurado no proxy/CDN, fora do código",
    ]),
    # C8 nasce vazia de propósito: não existe UMA regra de dependência
    # vulnerável no scanner. Enquanto não houver audit rodando, a categoria sai
    # como não verificada — nunca como "limpo".
    "C8": dict(capability_version=1, checks=[], known_gaps=[
        "nenhum check implementado: npm/pip/go/composer audit não é invocado",
        "lockfile não é lido nem comparado com base de CVE",
        "versão declarada em package.json/requirements.txt não é confrontada com nada",
    ]),
    "C9": dict(capability_version=1, checks=[
        dict(id="injecao_de_prompt_em_arquivo", titulo="Texto tentando direcionar a auditoria",
             regras=("C9-prompt-injection",)),
    ], known_gaps=[
        "arquivos de regra (.md, CLAUDE.md, AGENTS.md, .cursorrules, .mcp.json) estão fora "
        "da varredura — e para arquivo de regra da raiz o achado seria registro post-mortem, "
        "não barreira: o agente já leu o arquivo antes de a skill ativar",
        "instrução escondida em nome de arquivo ou em mensagem de commit",
    ]),
}


def _indexar_catalogo() -> dict[str, dict]:
    """Fecha o catálogo: extensões de cada check derivadas das próprias regras,
    e conferência de que toda regra pertence a exatamente um check.

    A conferência roda na importação de propósito. Regra nova sem check é
    exatamente o caminho por onde a cobertura volta a mentir — e falhar aqui
    custa um traceback, não um relatório verde errado."""
    por_regra = {r["id"]: r for r in REGRAS}
    indice: dict[str, dict] = {}
    vistas: set[str] = set()
    for cat, dados in CATALOGO.items():
        for chk in dados["checks"]:
            chk["cat"] = cat
            chk.setdefault("escopo", "arquivos")
            if "exts" not in chk:
                exts: set[str] | None = set()
                for rid in chk["regras"]:
                    regra = por_regra.get(rid)
                    if regra is None:          # regra sintética (entropia, checks de raiz)
                        continue
                    if "ext" not in regra:
                        exts = None
                        break
                    exts |= {e.lower() for e in regra["ext"]}
                chk["exts"] = sorted(exts) if exts else None
            for rid in chk["regras"]:
                if rid in vistas:
                    raise ErroDeExecucao(f"regra {rid} aparece em mais de um check do catálogo")
                vistas.add(rid)
                indice[rid] = chk
    orfas = sorted({r["id"] for r in REGRAS} - vistas)
    if orfas:
        raise ErroDeExecucao(
            f"regras sem check no catálogo: {orfas}. Regra sem check não entra em "
            "cobertura nenhuma — é exatamente por aí que a categoria volta a mentir.")
    return indice


INDICE_REGRA_CHECK = _indexar_catalogo()

RESULTADOS = ("sem_achados", "com_achados")
COBERTURAS = ("completa", "parcial", "nenhuma", "nao_aplicavel")


def _aplica(exts, chave: str) -> bool:
    return exts is None or chave in exts


def avaliar_cobertura(cobertura: dict, achados: list[dict]) -> tuple[list[dict], dict]:
    """Os dois eixos, no nível do CHECK; a categoria é derivada.

    `resultado` (o que achei) e `cobertura` (o quanto olhei) são propriedades
    diferentes e podem ser verdadeiras ao mesmo tempo: C4 que encontrou 2
    segredos E deixou 3 arquivos sem ler é, simultaneamente, `com_achados` e
    `parcial`. Um campo só de três valores obrigaria a escolher qual verdade
    contar — e a experiência diz qual das duas some.

    A palavra "limpo" só existe na interseção `sem_achados` + `completa`.
    """
    ext_projeto = cobertura.get("ext_do_projeto", {})
    total_projeto = sum(ext_projeto.values())
    lidos = [chave_ext(Path(a)) for a in cobertura.get("lidos", [])]
    nao_lidos = cobertura.get("nao_lidos", [])
    global_ = cobertura.get("degradacao_global", [])

    por_regra: dict[str, list[dict]] = {}
    for a in achados:
        if e_positivo(a):
            continue
        por_regra.setdefault(a.get("regra", ""), []).append(a)

    saida: list[dict] = []
    for cat, dados in CATALOGO.items():
        for chk in dados["checks"]:
            achados_do_check = [a for r in chk["regras"] for a in por_regra.get(r, [])]
            exts = chk["exts"]
            item = dict(id=chk["id"], cat=cat, titulo=chk["titulo"],
                        regras=list(chk["regras"]), escopo=chk["escopo"],
                        exts=exts, achados=len(achados_do_check),
                        resultado="com_achados" if achados_do_check else "sem_achados")

            if chk["escopo"] == "raiz":
                item.update(cobertura="completa",
                            motivo="verificação de raiz: enumera .env/.pem/.key e não depende "
                                   "do orçamento de arquivos",
                            aplicaveis=0, varridos=0, nao_lidos=0)
                saida.append(item)
                continue

            aplicaveis = (total_projeto if exts is None
                          else sum(n for e, n in ext_projeto.items() if e in exts))
            varridos = sum(1 for e in lidos if _aplica(exts, e))
            perdidos = [n for n in nao_lidos if _aplica(exts, n.get("ext", ""))]
            item.update(aplicaveis=aplicaveis, varridos=varridos, nao_lidos=len(perdidos))

            if exts is not None and aplicaveis == 0:
                # `nao_aplicavel` SÓ com evidência, e a evidência aqui é do
                # inventário independente (contou tudo que existe), não do
                # filtro de relevância — senão o estado seria autorreferente.
                item.update(cobertura="nao_aplicavel",
                            motivo=(f"nenhum arquivo {', '.join(exts)} entre os {total_projeto} "
                                    "arquivos de código do projeto (inventário independente)"))
            elif varridos == 0:
                item.update(cobertura="nenhuma",
                            motivo=("nenhum arquivo aplicável foi lido nesta execução"
                                    + (f" — {global_[0]}" if global_ else "")))
            elif global_ or perdidos:
                motivos = list(global_)
                if perdidos:
                    contas: dict[str, int] = {}
                    for n in perdidos:
                        contas[n["motivo"]] = contas.get(n["motivo"], 0) + 1
                    motivos.append(", ".join(f"{v} {k}" for k, v in sorted(contas.items())))
                item.update(cobertura="parcial",
                            motivo=(f"{varridos} de {varridos + len(perdidos)} arquivos "
                                    f"aplicáveis lidos — " + "; ".join(motivos)))
            else:
                item.update(cobertura="completa",
                            motivo=f"{varridos} de {varridos} arquivos aplicáveis lidos")
            saida.append(item)

    categorias = {}
    for cat, dados in CATALOGO.items():
        checks = [c for c in saida if c["cat"] == cat]
        efetivos = [c for c in checks if c["cobertura"] != "nao_aplicavel"]
        fora = [a for a in achados
                if a.get("categoria") == cat and not e_positivo(a)
                and a.get("regra", "") not in INDICE_REGRA_CHECK]
        if not checks:
            cob, motivo = "nenhuma", ("a categoria não tem nenhum check implementado — "
                                      "nada foi verificado aqui")
        elif not efetivos:
            # No nível da CATEGORIA `nao_aplicavel` não existe: "este projeto
            # não usa Supabase" não torna autorização inaplicável, torna o
            # detector supabase_rls inaplicável. Se todos os checks são N/A, o
            # que se pode dizer é que a categoria não foi verificada.
            cob, motivo = "nenhuma", ("todos os checks desta categoria são inaplicáveis a este "
                                      "projeto — a pergunta continua sem resposta")
        elif all(c["cobertura"] == "completa" for c in efetivos):
            cob, motivo = "completa", f"{len(efetivos)} check(s) executados por inteiro"
        elif any(c["cobertura"] in ("completa", "parcial") for c in efetivos):
            cob = "parcial"
            motivo = "; ".join(f"{c['id']}: {c['cobertura']}" for c in efetivos
                               if c["cobertura"] != "completa")
        else:
            cob, motivo = "nenhuma", "nenhum check desta categoria chegou a rodar"
        com_achado = any(c["resultado"] == "com_achados" for c in checks) or bool(fora)
        categorias[cat] = dict(
            resultado="com_achados" if com_achado else "sem_achados",
            cobertura=cob, motivo=motivo,
            capability_version=dados["capability_version"],
            known_gaps=list(dados["known_gaps"]),
            checks=[c["id"] for c in checks],
            achados_fora_do_catalogo=len(fora),
            limpo=(not com_achado) and cob == "completa")
    return saida, categorias


def e_limpo(cat_info: dict) -> bool:
    """A única definição de "limpo" que este código aceita."""
    return cat_info.get("resultado") == "sem_achados" and cat_info.get("cobertura") == "completa"


def montar_inventario(cobertura: dict) -> dict:
    """DOIS blocos, não um denominador só.

    Jogar node_modules no total produziria "4% de cobertura" — número
    tecnicamente correto e operacionalmente inútil, que treina o operador a
    ignorar a métrica. O denominador principal é o código do projeto;
    dependência e artefato aparecem contados ao lado, para que ninguém possa
    dizer que não sabia que existem.

    O grupo que importa é "tipo não reconhecido": é ali que aparece o próximo
    furo de cobertura.
    """
    inv = cobertura.get("inventario", {})
    codigo = dict(
        analisados=cobertura.get("varridos", 0),
        nao_reconhecidos=inv.get("nao_reconhecido", 0),
        acima_do_limite=inv.get("acima_do_limite", 0),
        ilegiveis=inv.get("ilegivel", 0),
        fora_da_raiz=inv.get("fora_da_raiz", 0),
        cortados_por_orcamento=cobertura.get("cortados", 0),
    )
    codigo["descobertos"] = sum(codigo.values())
    politica = dict(
        dependencias_e_vendor=inv.get("dependencia", 0),
        gerados_e_cache=inv.get("gerado", 0),
        lockfiles=inv.get("lockfile", 0),
        binarios=inv.get("binario", 0),
    )
    politica["total"] = sum(politica.values())
    return dict(codigo_do_projeto=codigo, excluidos_por_politica=politica,
                extensoes=dict(sorted(cobertura.get("ext_do_projeto", {}).items(),
                                      key=lambda kv: (-kv[1], kv[0]))[:25]))


def decidir_exit(dados: dict) -> int:
    """Contrato de saída — e ele contempla COBERTURA, não só severidade.

    Uma execução com 0 crítico e cobertura parcial saindo `0` seria recriar a
    falha-aberta exatamente na fronteira com o CI, que é onde ela custa mais
    caro: o gate aprova em silêncio. Os números importam menos que a regra —
    **parcial nunca é 0**.

      0  válida, sem achado bloqueante E cobertura requerida completa
      1  erro de execução ou violação de contrato (levantado como ErroDeExecucao)
      2  achado bloqueante (crítico/alto)
      3  auditoria incompleta (cobertura parcial, nenhuma, ou snapshot divergente)
    """
    visiveis = [a for a in dados.get("achados", []) if not e_positivo(a)]
    if any(a.get("severidade") in ("critico", "alto") for a in visiveis):
        return 2
    categorias = dados.get("categorias") or {}
    if not categorias or any(c.get("cobertura") != "completa" for c in categorias.values()):
        return 3
    return 0


# --------------------------------------------------------------------------
# Entropia (reforço do C4)
# --------------------------------------------------------------------------

RX_ATRIBUICAO = re.compile(
    r"\b(\w*(?:key|secret|token|password|senha|api|auth|cred)\w*)\s*[:=]\s*['\"]([^'\"\s]{20,})['\"]",
    re.IGNORECASE,
)

# Mesma regra com as aspas OPCIONAIS, para os formatos em que segredo não é
# escrito entre aspas. A entropia é a rede de segurança do C4; enquanto ela
# exigia aspas, ela caía junto com a regra de padrão nos mesmos arquivos.
RX_ATRIBUICAO_SEM_ASPAS = re.compile(
    r"\b(\w*(?:key|secret|token|password|senha|api|auth|cred)\w*)[ \t]*[:=][ \t]*['\"]?([^'\"\s]{20,})['\"]?",
    re.IGNORECASE,
)

# Extensões em que o valor costuma vir sem aspas.
EXT_SEM_ASPAS = {".yml", ".yaml", ".sh", ".tf", ".env", ".tfvars", ".properties", ".ini", ".conf"}


def valor_sem_aspas(p: Path) -> bool:
    """O arquivo é de um formato em que segredo é escrito sem aspas?"""
    return (p.suffix.lower() in EXT_SEM_ASPAS
            or p.name in ARQ_SEM_EXT
            or p.name.startswith(".env"))


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


def varrer(root: Path, arquivos: list[Path], stacks: list[str]) -> tuple[list[dict], dict]:
    """Varre e devolve (achados, diagnóstico).

    O diagnóstico não é log: é o que sustenta o eixo de cobertura. Arquivo que
    o scanner não conseguiu ler precisa aparecer contado — sumir em silêncio é
    o que fazia "categoria limpa" significar "ninguém olhou"."""
    achados: list[dict] = []
    vistos: set[str] = set()
    diag: dict[str, list[str]] = {"lidos": [], "ilegiveis": [], "fora_da_raiz": []}

    for p in arquivos:
        # Guarda redundante de propósito: a lista já vem filtrada, mas ler
        # arquivo de fora da raiz é exfiltração, não bug de cobertura — e o
        # custo de conferir de novo é um lstat.
        if not dentro_da_raiz(p, root):
            diag["fora_da_raiz"].append(rel_de(p, root))
            continue
        try:
            texto = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            diag["ilegiveis"].append(rel_de(p, root))
            continue
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        diag["lidos"].append(rel)
        linhas = texto.splitlines()
        eh_teste = bool(re.search(r"(test|spec|fixture|mock|__tests__|example)", rel, re.I))
        sem_aspas = valor_sem_aspas(p)

        for regra in REGRAS:
            if "ext" in regra and p.suffix.lower() not in regra["ext"]:
                continue
            if "caminho_exige" in regra and not regra["caminho_exige"].search(rel):
                continue
            if "caminho_nao" in regra and regra["caminho_nao"].search(rel):
                continue

            rx = regra["rx_sem_aspas"] if (sem_aspas and "rx_sem_aspas" in regra) else regra["rx"]
            for m in rx.finditer(texto):
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
                    # Mascarar é o DEFAULT: só sai cru a regra que declarou
                    # `mascarar=False`. Regra nova nasce protegida — o defeito
                    # anterior era o inverso, a regra nascia vazando.
                    trecho=trecho[:300] if regra.get("mascarar") is False else mascarar(trecho),
                    explicacao=regra["explica"], como_confirmar=regra["confirma"],
                    nota=nota, origem="padrao", estado="novo",
                ))

        # entropia — só informativo, para não inflar falso positivo
        for m in (RX_ATRIBUICAO_SEM_ASPAS if sem_aspas else RX_ATRIBUICAO).finditer(texto):
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
    return achados, diag


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
        if not dentro_da_raiz(p, root):
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
        if not dentro_da_raiz(p, root):
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

def raiz_do_estado() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or ""
    raiz = Path(base) if os.path.isabs(base) else Path.home() / ".local" / "state"
    return raiz / "ll-sec"


def identificador_do_repo(root: Path, explicito: str | None = None) -> str:
    """`<repo-id>` = hash do caminho absoluto resolvido + sufixo legível.

    Nada aqui pode derivar do CONTEÚDO do repositório: um repositório hostil
    forjaria a identidade de outro e herdaria as supressões dele — que é
    exatamente a fronteira que o 0.7 acabou de fechar, entrando pela porta dos
    fundos. Sinal de conteúdo pode INVALIDAR estado, nunca reivindicá-lo.
    """
    if explicito:
        limpo = re.sub(r"[^A-Za-z0-9_.-]+", "-", explicito).strip("-.")
        if not limpo:
            raise ErroDeExecucao("--repo-id vazio depois de higienizado")
        return limpo[:64]
    h = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    legivel = re.sub(r"[^A-Za-z0-9_-]+", "-", root.name).strip("-") or "repo"
    return f"{h}-{legivel[:40]}"


def _ids_da_pasta(p: Path) -> list:
    try:
        st = p.stat()
        return [st.st_dev, st.st_ino]
    except OSError:
        return [0, 0]


def abrir_estado(root: Path, repo_id: str | None = None) -> dict:
    """Abre (e cria) o diretório de estado do auditor, FORA do repositório.

    Duas armadilhas, uma em cada direção. Caminho sozinho reaproveita estado
    errado: apagar o repositório A e clonar B no mesmo caminho faria B herdar a
    triagem, os falsos positivos e os riscos aceitos de A — e depois de 0.7/0.9
    a memória tem autoridade sobre o que a auditoria cala, então isso é falha de
    segurança, não inconveniência. Conteúdo do repositório, por outro lado, não
    pode reivindicar identidade nenhuma.

    O que sobra é uma HEURÍSTICA CONSERVADORA, não uma identidade: casam sinais
    físicos (caminho canônico, dev/ino da raiz e do .git); qualquer divergência
    vira reset com aviso no relatório. Se o filesystem reciclar o mesmo inode no
    mesmo dev, a tripla volta a casar e a substituição passa — está declarado
    aqui de propósito, porque para ferramenta de segurança falso reset é sempre
    melhor que falso reaproveitamento.
    """
    rid = identificador_do_repo(root, repo_id)
    base = raiz_do_estado()
    pasta = base / rid
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    pasta.mkdir(parents=True, exist_ok=True)
    os.chmod(pasta, 0o700)

    agora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    st_raiz = _ids_da_pasta(root)
    st_git = _ids_da_pasta(root / ".git")
    atual = dict(canonical_path=str(root), st_dev=st_raiz[0], st_ino=st_raiz[1],
                 git_dev=st_git[0], git_ino=st_git[1],
                 ctime_raiz=int(root.stat().st_ctime) if root.exists() else 0,
                 mtime_raiz=int(root.stat().st_mtime) if root.exists() else 0,
                 first_seen=agora, repo_id=rid, id_explicito=bool(repo_id))

    arq_id = pasta / "identidade.json"
    reset, motivo, primeira = False, "", True
    if arq_id.exists():
        try:
            antigo = json.loads(arq_id.read_text(encoding="utf-8"))
            primeira = False
        except Exception:
            antigo, primeira = {}, True
        divergiu = [c for c in ("canonical_path", "st_dev", "st_ino", "git_dev", "git_ino")
                    if antigo.get(c) != atual[c]]
        if antigo and divergiu:
            reset = True
            motivo = ("a identidade física do repositório mudou desde a última execução "
                      f"({', '.join(divergiu)}); a linha de base anterior NÃO foi aplicada. "
                      "Mover, reclonar ou substituir o projeto começa do zero de propósito — "
                      "falso reset é melhor que herdar a memória de outro repositório.")
            carimbo = datetime.now().strftime("%Y%m%d-%H%M%S")
            for nome in ("estado.json", "triagem.json", "supressoes.json"):
                alvo = pasta / nome
                if alvo.exists():
                    alvo.rename(pasta / f"{nome}.pre-reset-{carimbo}")
        elif antigo:
            atual["first_seen"] = antigo.get("first_seen", agora)

    escrever_estado(arq_id, json.dumps(atual, ensure_ascii=False, indent=2))
    rel = pasta / "relatorios"
    rel.mkdir(parents=True, exist_ok=True)
    os.chmod(rel, 0o700)
    return dict(dir=pasta, relatorios=rel, identidade=atual,
                reset=reset, motivo_reset=motivo, primeira_vez=primeira or reset)


def escrever_estado(caminho: Path, texto: str) -> None:
    """Todo arquivo do estado nasce 0600. O que mora ali é o mapa de
    vulnerabilidade de TODOS os projetos da máquina reunidos num diretório só —
    a concentração é ativo novo e precisa ser tratada como tal."""
    caminho.write_text(texto, encoding="utf-8")
    os.chmod(caminho, 0o600)


def carregar_supressoes(estado_dir: Path) -> dict[str, str]:
    """Supressão efetiva: `supressoes.json` no estado do AUDITOR, fora do alvo.

    A skill lê, nunca escreve — aceitar risco é decisão do operador, não da
    ferramenta. O que mudou é de ONDE ela lê: enquanto a lista vinha de dentro
    do repositório auditado, o próprio auditado entregava, junto com o código,
    a lista dos achados que queria silenciados.
    """
    arq = estado_dir / "supressoes.json"
    if not arq.exists():
        return {}
    try:
        dados = json.loads(arq.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(dados, dict):
        return {}
    return {str(k): (str(v) if v else "(sem justificativa)") for k, v in dados.items()}


def ler_ignore_do_alvo(root: Path) -> dict:
    """`.ll-sec-ignore` do repositório auditado: INFORMAÇÃO, nunca instrução.

    O arquivo continua sendo lido — e o que ele pede aparece no relatório —,
    mas não silencia mais nada. Conteúdo do alvo é dado sob análise; deixá-lo
    escolher o que a auditoria cala é entregar o silêncio a quem está sendo
    auditado. Não há flag para religar isso: um CLAUDE.md hostil, que já está
    no contexto antes de a skill ativar, mandaria o agente usar a flag.
    """
    arq = root / ".ll-sec-ignore"
    info = dict(existe=False, arquivo=".ll-sec-ignore", pedidos=[], aplicado=False)
    if not arq.exists() or not dentro_da_raiz(arq, root):
        return info
    info["existe"] = True
    try:
        linhas = arq.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return info
    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = re.split(r"[\s|]+", linha, maxsplit=1)
        info["pedidos"].append(dict(
            fingerprint=partes[0][:64],
            justificativa=(partes[1].strip() if len(partes) > 1 else "(sem justificativa)")[:300]))
    return info


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


# `garantir_gitignore` foi REMOVIDA, não corrigida. Ela existia porque o
# relatório morava dentro do repositório auditado; agora o relatório sai em
# ~/.local/state/ll-sec/<repo-id>/relatorios/ e a skill passa a ter ZERO
# escrita dentro do alvo. Some com ela a checagem por substring que aceitava
# entrada comentada (`# ll-sec-relatorios/ (desativado)` devolvia "ja_estava" e
# o mapa de vulnerabilidades ficava versionável) e some a única exceção do
# contrato "somente leitura", cuja própria docstring admitia ser exceção.


def resolver_saida(root: Path, out_arg: str | None, estado: dict) -> Path:
    """Onde o relatório é gravado. Dentro da raiz auditada é ERRO, não opção.

    Não é preferência de estilo: saída dentro da árvore varrida realimenta a
    varredura seguinte (o findings.json vira achado do próximo scan) e devolve
    ao alvo o poder de plantar estado pré-fabricado."""
    if not out_arg:
        return estado["relatorios"]
    destino = Path(out_arg).expanduser()
    if not destino.is_absolute():
        destino = (Path.cwd() / destino)
    destino = destino.resolve()
    if destino == root or destino.is_relative_to(root):
        raise ErroDeExecucao(
            f"--out aponta para dentro do repositório auditado ({destino}). "
            "A skill não escreve nada dentro do alvo: sem --out, o relatório sai em "
            f"{estado['relatorios']}.")
    destino.mkdir(parents=True, exist_ok=True)
    return destino


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
.rolagem{overflow-x:auto;max-width:100%;-webkit-overflow-scrolling:touch}
.tab-leg{margin-top:12px;min-width:520px}
.tab-leg td{vertical-align:top;font-size:12.5px}
.leg-c{font-family:ui-monospace,Menlo,monospace;color:#79c0ff;font-weight:600;width:44px}
.leg-n{color:#f0f6fc;font-weight:600;white-space:nowrap}
.leg-m{white-space:nowrap;width:104px}
.leg-on{background:#1b1f26}
.pt-sim{font-size:11px;padding:2px 8px;border-radius:20px;background:#332b0f;border:1px solid #e3b341;color:#f0d074}
.pt-nao{font-size:11px;padding:2px 8px;border-radius:20px;background:#21262d;border:1px solid #30363d;color:#8b949e}
.leg-rod{font-size:12px;color:#8b949e;margin:11px 0 0}
.eixo{font-size:11px;padding:2px 9px;border-radius:20px;border:1px solid;white-space:nowrap;display:inline-block}
.e-limpo{background:#0f2f1c;border-color:#3fb950;color:#7ee787}
.e-achado{background:#3a2411;border-color:#ffa657;color:#ffc08a}
.e-nada{background:#21262d;border-color:#30363d;color:#8b949e}
.c-completa{background:#0f2f1c;border-color:#3fb950;color:#7ee787}
.c-parcial{background:#332b0f;border-color:#e3b341;color:#f0d074}
.c-nenhuma{background:#3d1418;border-color:#f85149;color:#ff9f96}
.c-na{background:#0d2d4d;border-color:#388bfd;color:#a5d6ff}
.sec-cob{margin:26px 0 12px;font-size:14px;font-weight:600;color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:7px}
.sec-cob:first-child{margin-top:0}
.inv{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.bloco-inv{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 17px}
.bloco-inv h3{margin:0 0 10px;font-size:13px;color:#f0f6fc;text-transform:uppercase;letter-spacing:.5px}
.sub-inv{text-transform:none;letter-spacing:0;color:#8b949e;font-weight:400;font-size:11.5px}
.linha-inv{display:flex;justify-content:space-between;gap:14px;padding:5px 0;border-bottom:1px solid #21262d;font-size:13px}
.linha-inv:last-of-type{border-bottom:none}
.linha-inv b{font-family:ui-monospace,Menlo,monospace;color:#f0f6fc}
.linha-inv.total{border-bottom:2px solid #30363d;font-weight:600}
.linha-inv.destaque span{color:#f0d074}.linha-inv.destaque b{color:#f0d074}
.linha-inv.total-inv{border-top:1px solid #30363d;font-weight:600;margin-top:4px}
.just{color:#8b949e;font-size:12px;text-align:right;max-width:60%}
.bloco-check{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:13px 17px;margin-bottom:12px}
.cab-check{display:flex;flex-wrap:wrap;align-items:center;gap:9px;margin-bottom:9px;font-size:14px;color:#f0f6fc}
.ver-cap{font-size:11px;color:#8b949e;font-family:ui-monospace,Menlo,monospace}
.sem-check{color:#ff9f96;font-size:12.5px}
.gaps{background:transparent;border:none;padding:0;margin:9px 0 0}
.gaps summary{font-size:12.5px;color:#8b949e;font-weight:500}
.gaps ul{margin:8px 0 0;padding-left:20px;font-size:12.5px;color:#c9d1d9}
.gaps li{margin-bottom:4px}
.lim{background:#161b22;border:1px solid #30363d;border-left:3px solid #e3b341;border-radius:0 9px 9px 0;padding:11px 15px;margin-bottom:10px;font-size:13px}
.lim b{color:#f0d074}
.aviso-ign{border-left-color:#f85149}.aviso-ign b{color:#ff9f96}
.amostra{margin-top:7px;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#8b949e;word-break:break-all}
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
@media (max-width:760px){
.wrap{padding:20px 12px 60px}
.leg-n{white-space:normal}
.tab-leg{min-width:720px}
.tab-leg td{font-size:12px}
.leg-m{width:auto}
}
@media print{body{background:#fff;color:#000}.tab{display:none}.painel{display:block!important}
.item,.card,.meta,details{background:#fff;border-color:#ccc;break-inside:avoid}
.tit,h1{color:#000}pre{background:#f6f8fa;color:#000}
.simples{background:#f0f6ff;color:#000}.simples b{color:#000}
.num{background:#e6edf3;color:#000;border:1px solid #999}
.selo{color:#000;background:#f6f8fa}.leg-n,.leg-c{color:#000}.leg-on{background:#f6f8fa}
.bloco-inv,.bloco-check,.lim{background:#fff;border-color:#ccc;break-inside:avoid}
.bloco-inv h3,.cab-check,.linha-inv b,.sec-cob{color:#000}
.eixo{color:#000;background:#f6f8fa}.gaps ul{color:#000}}
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


def num(v) -> str:
    """Milhar com ponto, do jeito que o operador lê."""
    try:
        return f"{int(v):,}".replace(",", ".")
    except (TypeError, ValueError):
        return esc(v)


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


ROTULO_COBERTURA = {
    "completa": ("c-completa", "cobertura completa"),
    "parcial": ("c-parcial", "cobertura parcial"),
    "nenhuma": ("c-nenhuma", "não verificado"),
    "nao_aplicavel": ("c-na", "não se aplica"),
}


def selo_resultado(info: dict) -> str:
    if e_limpo(info):
        return '<span class="eixo e-limpo">limpo</span>'
    if info.get("resultado") == "com_achados":
        return '<span class="eixo e-achado">com achado</span>'
    return '<span class="eixo e-nada">nada encontrado</span>'


def selo_cobertura(valor: str) -> str:
    cls, rot = ROTULO_COBERTURA.get(valor, ROTULO_COBERTURA["nenhuma"])
    return f'<span class="eixo {cls}">{esc(rot)}</span>'


def render_legenda(ctx: dict) -> str:
    """Tabela fixa com TODAS as categorias, agora em DOIS eixos.

    A marca antiga era binária — "com achado" ou "limpo" — e "limpo" saía por
    ausência de achado, inclusive para categoria que ninguém olhou e para
    categoria que não tem uma única regra implementada. Agora "o que achei" e
    "o quanto olhei" são colunas diferentes, e a palavra **limpo** só aparece
    na interseção `sem_achados` + `cobertura completa`.
    """
    categorias = ctx.get("categorias") or {}
    linhas = []
    for c, d in CATEGORIAS.items():
        info = categorias.get(c, dict(resultado="sem_achados", cobertura="nenhuma"))
        destaque = info.get("resultado") == "com_achados" or info.get("cobertura") != "completa"
        linhas.append(
            f'<tr class="{"leg-on" if destaque else ""}">'
            f'<td class="leg-c">{c}</td>'
            f'<td class="leg-n">{esc(d["nome"])}</td>'
            f'<td>{esc(d["simples"])}</td>'
            f'<td class="leg-m">{selo_resultado(info)}</td>'
            f'<td class="leg-m">{selo_cobertura(info.get("cobertura", "nenhuma"))}</td></tr>')
    return f"""<details class="legenda" open>
<summary>O que significa cada categoria (C1 a C9)</summary>
<div class="rolagem"><table class="tab-leg"><thead><tr>
<th>Sigla</th><th>Categoria</th><th>O que é, em uma frase</th>
<th>O que achei</th><th>O quanto olhei</th>
</tr></thead><tbody>{''.join(linhas)}</tbody></table></div>
<p class="leg-rod">São <b>duas perguntas diferentes</b>, e as duas são respondidas sempre.
<b>"Limpo"</b> só aparece quando nada foi encontrado <b>e</b> a cobertura foi completa.
<b>Não verificado</b> não é boa notícia: é ausência de resposta. A aba <b>Cobertura</b> diz,
check a check, o que rodou, o que ficou de fora e por quê.</p>
</details>"""


def render_inventario(inv: dict) -> str:
    """O denominador publicado — e os dois blocos separados de propósito."""
    cod = inv.get("codigo_do_projeto", {})
    pol = inv.get("excluidos_por_politica", {})
    linhas_cod = [
        ("descobertos", cod.get("descobertos", 0), "total"),
        ("analisados", cod.get("analisados", 0), ""),
        ("não reconhecidos", cod.get("nao_reconhecidos", 0), "destaque"),
        ("acima do limite de tamanho", cod.get("acima_do_limite", 0), ""),
        ("ilegíveis", cod.get("ilegiveis", 0), ""),
        ("apontando para fora da raiz", cod.get("fora_da_raiz", 0), ""),
        ("cortados pelo orçamento", cod.get("cortados_por_orcamento", 0), ""),
    ]
    linhas_pol = [
        ("dependências / vendor", pol.get("dependencias_e_vendor", 0)),
        ("gerados / cache / build", pol.get("gerados_e_cache", 0)),
        ("lockfiles", pol.get("lockfiles", 0)),
        ("binários", pol.get("binarios", 0)),
    ]
    html_cod = "".join(
        f'<div class="linha-inv {cls}"><span>{esc(k)}</span><b>{num(v)}</b></div>'
        for k, v, cls in linhas_cod)
    html_pol = "".join(
        f'<div class="linha-inv"><span>{esc(k)}</span><b>{num(v)}</b></div>'
        for k, v in linhas_pol)
    exts = inv.get("extensoes", {})
    html_ext = ", ".join(f"{esc(k)} ({v})" for k, v in list(exts.items())[:16]) or "—"
    return f"""<div class="inv">
<div class="bloco-inv"><h3>Código do projeto</h3>{html_cod}
<p class="leg-rod">O denominador que importa. <b>Não reconhecidos</b> é o número a vigiar:
são arquivos do projeto cujo tipo o scanner não sabe ler — é ali que aparece o próximo furo.</p></div>
<div class="bloco-inv"><h3>Excluídos por política <span class="sub-inv">(contados, não analisados)</span></h3>{html_pol}
<div class="linha-inv total-inv"><span>total</span><b>{num(pol.get('total', 0))}</b></div>
<p class="leg-rod">Ficam fora por decisão, não por descuido — e aparecem contados para que
ninguém possa dizer que não sabia que existem. Somar isto ao denominador principal produziria
uma taxa de cobertura tecnicamente correta e inútil.</p></div>
</div>
<p class="leg-rod">Tipos encontrados no código do projeto: {html_ext}</p>"""


def render_checks(ctx: dict) -> str:
    """Cobertura no nível do check — a categoria é derivada daqui."""
    checks = ctx.get("checks") or []
    categorias = ctx.get("categorias") or {}
    if not checks and not categorias:
        return ""
    blocos = []
    for c, cat_info in categorias.items():
        nome = CATEGORIAS.get(c, {}).get("nome", "")
        meus = [k for k in checks if k["cat"] == c]
        linhas = "".join(
            f'<tr><td class="leg-c">{esc(k["id"])}</td>'
            f'<td class="leg-n">{esc(k["titulo"])}</td>'
            f'<td class="leg-m">{"com achado (" + str(k["achados"]) + ")" if k["achados"] else "nada encontrado"}</td>'
            f'<td class="leg-m">{selo_cobertura(k["cobertura"])}</td>'
            f'<td>{esc(k.get("motivo", ""))}</td></tr>'
            for k in meus)
        if not meus:
            linhas = ('<tr><td colspan="5" class="sem-check">Nenhum check implementado nesta '
                      'categoria. Ela não pode aparecer como limpa — não foi verificada.</td></tr>')
        gaps = "".join(f"<li>{esc(g)}</li>" for g in cat_info.get("known_gaps", []))
        blocos.append(f"""<div class="bloco-check">
<div class="cab-check"><b>{c} · {esc(nome)}</b>
{selo_resultado(cat_info)} {selo_cobertura(cat_info.get("cobertura", "nenhuma"))}
<span class="ver-cap">catálogo v{cat_info.get("capability_version", 1)}</span></div>
<div class="rolagem"><table class="tab-leg"><tbody>{linhas}</tbody></table></div>
<details class="gaps"><summary>Lacunas declaradas desta categoria ({len(cat_info.get("known_gaps", []))})</summary>
<ul>{gaps}</ul></details></div>""")
    return "".join(blocos)


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
<div class="rolagem"><table class="tab-leg"><thead><tr>
<th>Nota</th><th>Nível</th><th>O que quer dizer</th><th>Nesta execução</th>
</tr></thead><tbody>{linhas_nota}</tbody></table></div>
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
    cats_info = ctx.get("categorias") or {}
    n_completa = sum(1 for d in cats_info.values() if d.get("cobertura") == "completa")
    n_limpa = sum(1 for d in cats_info.values() if e_limpo(d))
    linhas_cob = [
        ("Modo executado", ctx["modo"]),
        ("Stacks detectadas", ", ".join(ctx["recon"]["stacks"]) or "nenhuma reconhecida"),
        ("Referências consultadas", ", ".join(ctx["recon"]["referencias"])),
        ("Categorias com cobertura completa", f"{n_completa} de {len(CATEGORIAS)}"),
        ("Categorias limpas (nada achado E cobertura completa)", f"{n_limpa} de {len(CATEGORIAS)}"),
        ("Relatório gravado em", ctx.get("saida", "")),
        ("Estado do auditor", ctx.get("estado_dir", "")),
        ("Escrita dentro do repositório auditado", "nenhuma"),
    ]
    if cob.get("motivo_corte"):
        linhas_cob.append(("Motivo do corte", cob["motivo_corte"]))
    tabela_cob = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in linhas_cob)

    lims = ctx.get("limitacoes", []) or []
    if lims:
        itens_lim = []
        for lim in lims:
            if isinstance(lim, dict):
                amostra = lim.get("itens") or []
                extra = (f'<div class="amostra">{esc(", ".join(map(str, amostra[:12])))}'
                         f'{" …" if len(amostra) > 12 else ""}</div>' if amostra else "")
                itens_lim.append(f'<div class="lim"><b>{esc(lim.get("tipo", "limitação"))}</b> — '
                                 f'{esc(lim.get("descricao", ""))}{extra}</div>')
            else:
                itens_lim.append(f'<div class="lim">{esc(lim)}</div>')
        bloco_lim = ('<div class="sec-cob">O que esta execução NÃO fez</div>'
                     + "".join(itens_lim))
    else:
        bloco_lim = ('<div class="sec-cob">O que esta execução NÃO fez</div>'
                     '<div class="lim">Nenhuma limitação registrada além das lacunas de '
                     'catálogo listadas por categoria.</div>')

    ign = ctx.get("ignore_do_alvo") or {}
    if ign.get("existe"):
        pedidos = "".join(
            f'<div class="linha-inv"><span>fp {esc(q.get("fingerprint", ""))}</span>'
            f'<span class="just">{esc(q.get("justificativa", ""))}</span></div>'
            for q in ign.get("pedidos", [])[:40])
        bloco_ign = f"""<div class="sec-cob">O que o repositório pediu para ignorar</div>
<div class="lim aviso-ign"><b>O repositório auditado traz um <code>.ll-sec-ignore</code> pedindo
para ignorar {len(ign.get('pedidos', []))} achado(s). O pedido NÃO foi aplicado.</b>
Conteúdo do alvo é dado sob análise, nunca instrução: deixar o auditado escolher o que a
auditoria cala é entregar o silêncio a quem está sendo auditado. Para aceitar um risco de
verdade, o registro vai em <code>supressoes.json</code>, no estado do auditor.
{pedidos}</div>"""
    else:
        bloco_ign = ""

    reset = ctx.get("reset_de_identidade") or ""
    bloco_reset = (f'<div class="lim aviso-ign"><b>Linha de base reiniciada.</b> {esc(reset)}</div>'
                   if reset else "")

    tabs.append('<div class="tab" data-alvo="p-cob">Cobertura</div>')
    paineis.append(
        '<div class="painel" id="p-cob">'
        + bloco_reset
        + '<div class="sec-cob">Inventário do repositório</div>'
        + render_inventario(ctx.get("inventario") or montar_inventario(cob))
        + '<div class="sec-cob">Resumo da execução</div>'
        + f'<table>{tabela_cob}</table>'
        + '<div class="sec-cob">Cobertura check a check</div>'
        + '<p class="leg-rod">A cobertura da categoria é <b>derivada</b> dos checks — nunca '
          'declarada direto. E "completa" quer dizer <b>execução completa da capacidade '
          'declarada</b>, nunca "provamos que não existe falha": as lacunas conhecidas de cada '
          'categoria estão listadas junto, porque lacuna implícita é como categoria vazia '
          'consegue parecer limpa.</p>'
        + render_checks(ctx)
        + bloco_lim + bloco_ign
        + "</div>")

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
ticket público e não mande por canal inseguro. Ele foi gravado <b>fora do repositório auditado</b>
(<code>{esc(ctx.get('saida', ''))}</code>), com permissão 600 — a auditoria não escreveu um byte
dentro do projeto.</div>
<div class="meta">{uso_txt}</div>
{bloco_diff}
<div class="placar">{placar}</div>
{legenda_notas}\n{render_legenda(ctx)}
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
    if not root.is_dir():
        raise ErroDeExecucao(f"--root não é um diretório: {root}")
    # O estado do auditor vive FORA do repositório auditado. Estado que
    # influencia decisão (supressão, triagem, linha de base) não pode ficar do
    # lado de dentro: repo hostil traria um estado.json fabricado e o diff da
    # primeira execução já nasceria mentindo "9 resolvidos".
    estado = abrir_estado(root, getattr(args, "repo_id", None))
    out = resolver_saida(root, args.out, estado)

    recon = detectar_stacks(root)
    arquivos, cobertura = listar_arquivos(root, args.mode, args.since)
    achados, diag = varrer(root, arquivos, recon["stacks"])
    absorver_diagnostico(cobertura, diag)

    ignore_do_alvo = ler_ignore_do_alvo(root)
    if ignore_do_alvo["existe"]:
        cobertura["limitacoes"].append(dict(
            tipo="ignore_do_alvo",
            descricao=(f"o repositório auditado pede, no .ll-sec-ignore, para ignorar "
                       f"{len(ignore_do_alvo['pedidos'])} achado(s). O pedido é informação de "
                       "auditoria, não instrução: NADA foi silenciado por causa dele."),
            afeta="nenhum", itens=[q["fingerprint"] for q in ignore_do_alvo["pedidos"][:40]]))

    sup = carregar_supressoes(estado["dir"])
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
    caminho_triagem = estado["dir"] / "triagem.json"
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
    caminho_estado = estado["dir"] / "estado.json"
    try:
        anteriores = json.loads(caminho_estado.read_text(encoding="utf-8")).get("fingerprints", [])
    except Exception:
        anteriores = []

    diff = aplicar_diff(restantes, caminho_estado)
    if estado["reset"]:
        cobertura["limitacoes"].append(dict(
            tipo="reset_de_identidade", descricao=estado["motivo_reset"],
            afeta="diff", itens=[]))

    # Os dois eixos são calculados AQUI, sobre a lista bruta, e recalculados no
    # render sobre a lista final: `cobertura` é fato de execução (não muda com a
    # triagem), `resultado` é a lista que o operador de fato vai ver.
    checks, categorias = avaliar_cobertura(cobertura, restantes + suprimidos)

    payload = dict(
        projeto=root.name, root=str(root), modo=args.mode,
        gerado_em=datetime.now().strftime("%d/%m/%Y %H:%M"),
        recon=recon, cobertura=cobertura, achados=restantes,
        suprimidos=suprimidos, diff=diff,
        limitacoes=cobertura["limitacoes"], uso={}, estado_anterior=anteriores,
        ignore_do_alvo=ignore_do_alvo, estado_dir=str(estado["dir"]),
        identidade=estado["identidade"], reset_de_identidade=estado["motivo_reset"],
        saida=str(out), checks=checks, categorias=categorias,
        inventario=montar_inventario(cobertura),
    )
    destino = out / "findings.json"
    escrever_estado(destino, json.dumps(payload, ensure_ascii=False, indent=2))

    # O estado NÃO é gravado aqui de propósito: quem fecha a execução é o render,
    # que conhece a lista final depois da triagem. Gravar os achados crus faria a
    # próxima execução comparar contra ruído que nunca chegou ao relatório.

    resumo = {s: len([a for a in restantes if a["severidade"] == s]) for s in SEVS}
    print(json.dumps({"findings_json": str(destino), "total": len(restantes),
                      "por_severidade": resumo, "suprimidos": len(suprimidos),
                      "diff": diff, "recon": recon,
                      "inventario": payload["inventario"],
                      "categorias": {c: {k: v for k, v in d.items()
                                         if k in ("resultado", "cobertura", "limpo")}
                                     for c, d in categorias.items()},
                      "limitacoes": [l["descricao"] for l in cobertura["limitacoes"]],
                      "estado_dir": str(estado["dir"]),
                      "ignore_do_alvo": ignore_do_alvo,
                      "escrita_no_alvo": "nenhuma",
                      "exit_code": decidir_exit(payload)}, ensure_ascii=False, indent=2))
    return 0 if getattr(args, "exit_zero", False) else decidir_exit(payload)


def cmd_render(args):
    dados = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    root = Path(args.root).resolve()
    # A raiz vem da linha de comando, não do findings.json: o arquivo passa pelas
    # mãos do agente entre o scan e o render, e caminho de escrita não é campo
    # que dado de entrada tenha o direito de escolher.
    if dados.get("root") and Path(dados["root"]).resolve() != root:
        raise ErroDeExecucao(
            f"o findings.json foi gerado para {dados['root']}, mas --root aponta para {root}. "
            "Rode o render com a mesma raiz do scan.")
    estado = abrir_estado(root, getattr(args, "repo_id", None))
    out = resolver_saida(root, args.out, estado)

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

    # O eixo `resultado` é recalculado sobre a lista FINAL (o agente rebaixou,
    # descartou e acrescentou achados); o eixo `cobertura` não se recalcula
    # aqui, porque é fato da execução do scan e triagem não muda o que foi lido.
    cob_scan = dados.get("cobertura", {}) or {}
    checks, categorias = avaliar_cobertura(cob_scan, dados["achados"] + dados.get("suprimidos", []))
    dados["checks"], dados["categorias"] = checks, categorias
    dados.setdefault("inventario", montar_inventario(cob_scan))

    modo_label = {"completa": "completo", "rapida": "rapido"}.get(
        dados.get("modo", ""), dados.get("modo", "") or "run")
    proj = re.sub(r"[^A-Za-z0-9_-]+", "-", dados.get("projeto", "projeto")).strip("-") or "projeto"
    nome = f"ll-sec-{proj}-{modo_label}-{datetime.now().strftime('%Y-%m-%d-%H%M')}.html"
    destino = out / nome
    dados["saida"] = str(out)
    dados["estado_dir"] = str(estado["dir"])
    escrever_estado(destino, render_html(dados))

    # Memória de triagem: cada achado da lista final grava sua classificação por
    # fingerprint. Na próxima varredura o scan pré-aplica isso e marca o item
    # como "conhecido" — o diff para de acusar novidade no que já foi triado.
    tri_path = estado["dir"] / "triagem.json"
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
    escrever_estado(tri_path, json.dumps(tri, ensure_ascii=False, indent=1))

    # Fecha a execução: o estado passa a ser a lista que o operador de fato viu.
    escrever_estado(estado["dir"] / "estado.json", json.dumps(
        {"data": dados.get("gerado_em", ""), "modo": dados.get("modo", ""),
         "fingerprints": [a["fingerprint"] for a in dados["achados"]]},
        ensure_ascii=False, indent=2))
    saida_exit = decidir_exit(dados)
    print(json.dumps({"html": str(destino), "achados": len(dados["achados"]),
                      "estado_dir": str(estado["dir"]),
                      "categorias": {c: {k: v for k, v in d.items()
                                         if k in ("resultado", "cobertura", "limpo")}
                                     for c, d in categorias.items()},
                      "escrita_no_alvo": "nenhuma",
                      "exit_code": saida_exit}, ensure_ascii=False, indent=2))
    return 0 if getattr(args, "exit_zero", False) else saida_exit


def main():
    ap = argparse.ArgumentParser(description="ll-sec — varredura de segurança somente-leitura")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("recon"); p.add_argument("--root", default="."); p.set_defaults(f=cmd_recon)

    ajuda_out = ("pasta de saída — precisa ficar FORA do repositório auditado. "
                 "Sem --out, sai no estado do auditor (~/.local/state/ll-sec/<repo-id>/relatorios)")
    ajuda_id = ("identificador explícito do estado, para continuar a mesma linha de base "
                "depois de mover ou reclonar o projeto")

    p = sub.add_parser("scan")
    p.add_argument("--root", default=".")
    p.add_argument("--mode", choices=["rapida", "completa", "diff"], default="rapida")
    p.add_argument("--out", default=None, help=ajuda_out)
    p.add_argument("--repo-id", dest="repo_id", default=None, help=ajuda_id)
    p.add_argument("--since", default=None, help="commit de referência para o modo diff")
    p.add_argument("--exit-zero", dest="exit_zero", action="store_true",
                   help="sempre sair com 0, mesmo com achado bloqueante ou cobertura parcial")
    p.set_defaults(f=cmd_scan)

    p = sub.add_parser("render")
    p.add_argument("--root", default=".")
    p.add_argument("--out", default=None, help=ajuda_out)
    p.add_argument("--repo-id", dest="repo_id", default=None, help=ajuda_id)
    p.add_argument("--findings", required=True)
    p.add_argument("--uso", default=None, help="JSON do session_usage.py")
    p.add_argument("--exit-zero", dest="exit_zero", action="store_true",
                   help="sempre sair com 0, mesmo com achado bloqueante ou cobertura parcial")
    p.set_defaults(f=cmd_render)

    args = ap.parse_args()
    try:
        return args.f(args) or 0
    except ErroDeExecucao as e:
        print(f"ll-sec: ERRO — {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
