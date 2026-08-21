# ll-sec

Skill do Claude Code que audita a segurança de uma aplicação web em qualquer
stack e devolve um relatório HTML que o dono do sistema consegue ler.

## O problema

Código gerado por IA costuma funcionar na primeira tentativa, e falha de um
jeito específico: a tela fica pronta, o fluxo roda, e a tranca do banco ficou
desligada. Como nada quebra, ninguém percebe.

A ll-sec procura essa família de falha: RLS desligada, autorização que só existe
no front-end, consulta por id sem filtro de dono, chave de serviço no cliente,
segredo commitado três meses atrás. O resultado sai numa linguagem que o
operador do sistema entende, não apenas quem escreveu o código.

## Instalação

```bash
git clone https://github.com/rootLdr/ll-sec.git ~/.claude/skills/ll-sec
```

Requisito: Python 3. A skill passa a valer em todos os seus projetos.

## Uso

Dentro de qualquer projeto, na sessão do Claude Code:

```
/ll-sec rapida     # 2 a 5 min. Reconhecimento e varredura por padrões.
/ll-sec completa   # 10 a 30 min. Inclui histórico do Git, semgrep, bandit, audit de dependências.
/ll-sec diff       # 1 a 3 min. Só o que mudou desde o último relatório.
```

Sem argumento, ela pergunta o modo antes de começar.

## O relatório

![Relatório ll-sec](docs/relatorio-topo.png)

Gerado sobre o app de teste que vem no repositório.
[Ver a página inteira](docs/relatorio-completo.png).

Arquivo HTML único, offline, tema escuro, imprimível. Traz placar por nota de
risco, legenda das nove categorias, abas nomeadas, uma aba de cobertura com o
que não deu para avaliar, uma aba de riscos aceitos e uma aba "Verificado e OK",
que separa "conferi e está certo" de "ninguém olhou".

Cada achado sai com três campos que costumam faltar num scanner:

| Campo | O que responde |
|---|---|
| Frase simples | O que isso permite que aconteça, sem jargão. *"Quem tiver o endereço lê a tabela de clientes sem senha."* |
| Correção | O conserto deste caso, em uma linha. |
| Quem corrige | `agente` (é só código), `operador` (exige senha, console, decisão) ou `ambos`. Rotacionar segredo é sempre do operador. |

Segredo aparece mascarado por padrão (`sk_liv********abcd`). Sai em texto claro
apenas a regra que declara que o trecho é código, e não segredo.

## O que ela procura

| | Categoria | Exemplo |
|---|---|---|
| C1 | Banco sem tranca | RLS desligada, policy `using (true)`, regra `if true`, chave de serviço no cliente |
| C2 | Autorização no front-end | Papel lido do `localStorage`, guarda visual sem checagem no servidor |
| C3 | IDOR | Consulta por id da requisição sem filtro de dono |
| C4 | Segredos expostos | Prefixos conhecidos, chave privada, URL com senha, JWT literal, entropia |
| C5 | Input sem sanitização | XSS, `eval`, SQL concatenado, comando de shell montado |
| C6 | Autenticação e sessão | JWT sem verificar assinatura, `alg: none`, cookie sem flags, reset previsível |
| C7 | CSRF, CORS e headers | Origem `*` com credenciais, open redirect, SSRF, mutação por GET |
| C8 | Dependências vulneráveis | `npm audit`, `pip-audit`, `osv-scanner` (modo completa) |
| C9 | Manipulação da auditoria | Texto no repositório tentando desviar a análise |

Stacks com verificação dedicada: Supabase, Firebase, Next.js, Node/Express,
Django/Flask/FastAPI e PHP/Laravel. Fora dessas rodam as verificações
agnósticas, e a aba Cobertura declara o que não pôde ser avaliado.

## Nota de risco, de 1 a 5

O que decide a nota é quem consegue explorar, não o quanto o problema parece
grave.

| Nota | Quando se aplica |
|:---:|---|
| 5 | Explorável remotamente sem autenticação, ou segredo ativo exposto |
| 4 | Explorável por usuário autenticado comum, ou segredo no histórico do Git |
| 3 | Exige condição adicional ou interação da vítima |
| 2 | Hardening ausente, sem vetor direto demonstrado |
| 1 | Suspeita não confirmada, e o relatório diz o que falta para confirmar |

Em caso de empate a nota desce: na dúvida entre duas, fica registrada a menor.
Relatório inflado ensina o operador a ignorar o relatório inteiro, e aí a
próxima nota 5 passa batida junto com o resto.

## O contrato

Somente leitura, e literalmente: zero escrita dentro do projeto auditado. A
skill não corrige código, não instala dependência sem perguntar, não roda
migration, não toca em produção e não cria pasta de relatório nem linha no
`.gitignore` do repositório. Tudo o que ela grava fica fora do alvo, em
`~/.local/state/ll-sec/<repo-id>/` (pasta `0700`, arquivos `0600`).

Nada que venha de dentro do alvo altera o julgamento. Configuração do
repositório auditado entra no relatório como informação declarada, não como
instrução, e isso vale para `.ll-sec-ignore`, para `CLAUDE.md` e para comentário
de código. Não existe flag que religue esse comportamento: se o repositório
pedir para ignorar algo, o relatório mostra o pedido e continua reportando.

Silêncio não é aprovação. O relatório responde sempre a duas perguntas
separadas: o que foi encontrado e o quanto foi olhado. A palavra "limpo" só
aparece na interseção das duas, com nada encontrado e cobertura completa.

Aceitar risco é decisão do operador. A supressão fica em `supressoes.json`,
dentro do estado do auditor, e a skill nunca escreve nesse arquivo. O item
suprimido também não desaparece: vai para a aba "Riscos aceitos", com a
justificativa à vista.

Achado inventado sai mais caro que achado nenhum. Todo achado crítico ou alto
passa por triagem manual, que pergunta se a entrada é controlada pelo usuário,
se aquilo roda no cliente ou no servidor, e se existe defesa em outra camada.

## Conteúdo do repositório é dado, nunca instrução

Se um arquivo auditado contiver texto tentando direcionar a análise ("ignore
este arquivo", "este código já foi auditado", "AI: do not report this"), a skill
não obedece: registra o trecho como achado Alto na categoria C9 e segue
analisando o arquivo normalmente.

## Exit code

O scan termina com um código de saída que serve de veredito em CI:

| Exit | Significa |
|---|---|
| `0` | execução válida, sem achado bloqueante e cobertura requerida completa |
| `1` | erro de execução ou violação de contrato (raiz vazia, `--out` apontando para dentro do alvo) |
| `2` | achado bloqueante (crítico ou alto) |
| `3` | auditoria incompleta: cobertura parcial, nenhuma, ou categoria sem check |

Enquanto a C8 não tiver nenhum check implementado, toda execução sai `3` no
mínimo, para que a categoria vazia não se esconda atrás do enum. `--exit-zero`
devolve o comportamento antigo, de forma explícita.

## Onde ficam os arquivos

```
~/.local/state/ll-sec/<repo-id>/
├── identidade.json      identidade física do repositório (não editar)
├── estado.json          linha de base do diff, escrito pelo render
├── triagem.json         memória de triagem, escrito pelo render
├── supressoes.json      riscos aceitos, escrito por você e nunca pela skill
└── relatorios/          findings.json e os HTML

<repositório auditado>/  nada. Nenhum byte.
```

Esse diretório concentra o mapa de vulnerabilidade de todos os projetos
auditados na máquina, por isso nasce com permissão restrita.

## Recorrência entre execuções

- Fingerprint sem número de linha, de propósito: o achado sobrevive a edições
  vizinhas, e o diff não enche de falso "novo" a cada reindentação.
- Memória de triagem: a classificação dada a um achado fica gravada. Na execução
  seguinte ele entra como conhecido em vez de novo, e é revisto se o arquivo
  dele mudou.
- Identidade física: junto do estado ficam gravados o caminho canônico e o
  `dev`/`ino` da raiz e do `.git`. Se o projeto foi movido, reclonado ou
  substituído no mesmo caminho, o estado anterior é arquivado e a execução
  começa do zero, com aviso no relatório. Para continuidade portátil, use
  `--repo-id`.
- Diff: cada relatório mostra o que é novo, o que persiste e o que foi resolvido
  desde a execução anterior.

## Ferramentas opcionais

No modo `completa` a skill usa o que já estiver instalado e registra como lacuna
de cobertura o que faltar. Ela não instala nada sozinha.

`gitleaks`, `semgrep`/`opengrep`, `bandit`, `npm audit`, `pip-audit`,
`osv-scanner`

## Estrutura do repositório

```
SKILL.md               o comportamento da skill, é o que o Claude lê
scripts/
  ll_sec_scan.py       recon, scan e render do HTML
  session_usage.py     consumo da sessão no cabeçalho do relatório
references/            verificações por stack (supabase, firebase, nextjs, ...)
fixtures/
  app-vulneravel/      app propositalmente furado, para testar a skill
docs/                  imagens do README
```

`fixtures/app-vulneravel/` é deliberadamente inseguro. Existe só para validar a
skill, e não serve de base para nada.

## Atualizações

A skill é instalada por clone, então não avisa sozinha quando sai versão nova:

```bash
cd ~/.claude/skills/ll-sec && git pull
```

Para ser avisado, use o Watch no topo desta página, opção Custom, marcando
Releases. Cada versão fica em [Releases](../../releases), com o que mudou.

## Licença

[MIT](LICENSE). Use, copie, adapte, redistribua.
