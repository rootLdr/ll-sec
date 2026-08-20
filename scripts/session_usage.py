#!/usr/bin/env python3
"""
Lê o consumo da sessão atual do Claude Code (modelo + tokens) para o cabeçalho
do relatório do ll-sec.

O Claude Code grava um JSONL por sessão em
  ~/.claude/projects/<caminho-do-projeto-com-hifens>/<session-id>.jsonl
Cada linha é um evento; as de `type: assistant` carregam `message.model` e
`message.usage` com a contagem de tokens.

Esse formato é interno e pode mudar sem aviso. Por isso, qualquer surpresa aqui
resulta em `{"disponivel": false, "motivo": ...}` — um relatório sem o bloco de
consumo é aceitável; um relatório com número inventado, não.

Uso:
  session_usage.py [--projeto /caminho/do/projeto] [--sessao <id>]

Só stdlib, Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def dir_do_projeto(projeto: Path) -> Path:
    """O Claude Code troca '/' e '.' do caminho absoluto por '-'."""
    chave = str(projeto.resolve()).replace("/", "-").replace(".", "-").replace("_", "-")
    return Path.home() / ".claude" / "projects" / chave


def escolher_jsonl(base: Path, sessao: str | None) -> Path | None:
    if not base.is_dir():
        return None
    if sessao:
        alvo = base / f"{sessao}.jsonl"
        return alvo if alvo.exists() else None
    arquivos = sorted(base.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return arquivos[0] if arquivos else None


def somar(caminho: Path) -> dict:
    total = {"input_tokens": 0, "output_tokens": 0,
             "cache_read_tokens": 0, "cache_creation_tokens": 0}
    modelos: dict[str, int] = {}
    mensagens = 0

    with caminho.open(encoding="utf-8", errors="replace") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                ev = json.loads(linha)
            except json.JSONDecodeError:
                continue  # linha parcial no fim do arquivo é normal com a sessão viva
            if ev.get("type") != "assistant":
                continue
            msg = ev.get("message") or {}
            uso = msg.get("usage") or {}
            if not uso:
                continue
            mensagens += 1
            modelo = msg.get("model")
            if modelo:
                modelos[modelo] = modelos.get(modelo, 0) + 1
            total["input_tokens"] += uso.get("input_tokens", 0) or 0
            total["output_tokens"] += uso.get("output_tokens", 0) or 0
            total["cache_read_tokens"] += uso.get("cache_read_input_tokens", 0) or 0
            total["cache_creation_tokens"] += uso.get("cache_creation_input_tokens", 0) or 0

    if not mensagens:
        return {"disponivel": False,
                "motivo": "nenhuma mensagem com contagem de tokens no arquivo da sessão"}

    principal = max(modelos, key=modelos.get) if modelos else "desconhecido"
    return {"disponivel": True, "modelo": principal, "mensagens": mensagens,
            "arquivo": str(caminho), **total,
            "total_tokens": total["input_tokens"] + total["output_tokens"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projeto", default=os.getcwd())
    ap.add_argument("--sessao", default=None)
    args = ap.parse_args()

    try:
        base = dir_do_projeto(Path(args.projeto))
        arquivo = escolher_jsonl(base, args.sessao)
        if arquivo is None:
            print(json.dumps({"disponivel": False,
                              "motivo": f"nenhum JSONL de sessão em {base}"},
                             ensure_ascii=False))
            return 0
        print(json.dumps(somar(arquivo), ensure_ascii=False))
    except Exception as e:  # o relatório nunca deve falhar por causa deste bloco
        print(json.dumps({"disponivel": False, "motivo": f"{type(e).__name__}: {e}"},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
