# PHP / Laravel

## Laravel

- **Mass assignment**: `$model->fill($request->all())` ou `Model::create($request->all())`
  com `$fillable` frouxo (ou `$guarded = []`) deixa o usuário mandar
  `is_admin=1` no formulário. Achado **Alto**.
- **Autorização**: `Gate`, `Policy` ou `$this->authorize(...)` precisa existir na
  ação, não só no menu. Rota com `auth` mas sem policy é IDOR à espera:
  `Pedido::find($id)` sem `where('user_id', auth()->id())`.
- **Blade**: `{{ $x }}` escapa; `{!! $x !!}` **não**. Com dado de usuário, é XSS.
- **SQL**: `DB::raw`, `whereRaw`, `selectRaw` com interpolação. Use bindings.
- **APP_DEBUG=true** em produção: a página de erro do Ignition expõe variáveis de
  ambiente, incluindo credenciais. **Crítico**.
- **APP_KEY** versionado: quebra a criptografia de cookies e sessões.
- `.env` commitado — confira também o histórico do Git, não só o HEAD.
- Storage público: `php artisan storage:link` com upload sem validar extensão e
  servindo do mesmo domínio permite hospedar `.php` ou HTML com script.
- `Route::any` e `Route::get` para ações que gravam: CSRF e pré-carregamento.
- Middleware `VerifyCsrfToken` com rotas no `$except`: cada exceção precisa de motivo.

## PHP puro

- `$_GET` / `$_POST` / `$_REQUEST` direto em `mysqli_query`, `include`, `require`,
  `file_get_contents`, `unlink`, `system`, `exec`: injeção de SQL, LFI/RFI e
  comando. Tudo **Crítico** quando a entrada é do usuário.
- `include $_GET['page']` é execução remota, não só leitura de arquivo.
- `unserialize` sobre entrada de usuário: object injection.
- `md5`/`sha1` para senha: use `password_hash`/`password_verify`.
- `extract($_POST)` cria variáveis a partir da requisição — sobrescreve o que quiser.
- Sessão: `session.cookie_httponly`, `cookie_secure`, `cookie_samesite` no `php.ini`
  ou via `session_set_cookie_params`.

## Dependências

`composer audit` (modo completa). Registre em Cobertura se não estiver disponível.
