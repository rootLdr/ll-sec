# Python — Django, Flask, FastAPI

## Comum às três

- `DEBUG = True` / `app.run(debug=True)` em produção: página de erro com stack,
  variáveis locais e, no Flask, um console interativo que executa código. Se
  chegar a produção, é **Crítico**.
- `SECRET_KEY` fixo no código: assina sessão e token de reset. Quem lê o repositório
  falsifica sessão.
- `ALLOWED_HOSTS = ["*"]` (Django) facilita envenenamento de header Host.
- `pickle.loads`, `yaml.load` sem `SafeLoader`, `eval`, `exec` sobre dado de
  requisição: execução remota de código.
- `subprocess` com `shell=True` e string montada; `os.system(f"...")`: injeção de comando.
- `verify=False` em `requests`: TLS sem validação, abre man-in-the-middle.

## Django

- **ORM protege de SQL injection; `raw()` e `extra()` não.** Procure
  `.raw(`, `.extra(`, `cursor.execute(` com f-string ou `%` — parametrizar.
- Views sem `@login_required` / `LoginRequiredMixin`, ou com login mas sem checar
  objeto: `get_object_or_404(Pedido, pk=pk)` sem `user=request.user` é IDOR.
- `csrf_exempt` em view que grava: remove a proteção de CSRF.
- `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`,
  `SECURE_HSTS_SECONDS` ausentes: hardening (**Baixo**).
- `|safe` e `mark_safe` em template com dado de usuário: XSS.
- Serializer do DRF com `fields = "__all__"` expõe campo novo sem ninguém notar.

## Flask

- `render_template_string` com entrada do usuário: **SSTI** — leva a execução de
  código, não é só XSS. Severidade Crítica quando a entrada é controlada.
- `session` do Flask é assinada, **não criptografada**: o conteúdo é legível pelo
  usuário. Nada sensível ali dentro.
- `send_file` / `send_from_directory` com nome vindo da requisição: path traversal.
- Sem Flask-WTF/CSRFProtect em formulário com cookie de sessão: CSRF.

## FastAPI

- Dependência de autenticação declarada mas não aplicada à rota (esqueceram o
  `Depends`) — compare a lista de rotas com as que têm a dependência.
- `response_model` ausente devolve o objeto do banco inteiro, incluindo hash de
  senha; com Pydantic, `response_model` é também controle de vazamento.
- `CORSMiddleware` com `allow_origins=["*"]` e `allow_credentials=True`.
- OAuth2/JWT: confirme que há `jwt.decode(..., key, algorithms=[...])` com
  algoritmo fixo. `options={"verify_signature": False}` é **Crítico**.

## Dependências

`pip-audit -f json` ou `safety check --json` (modo completa). Sem ferramenta,
liste o que está com major muito atrasado e registre cobertura parcial.
