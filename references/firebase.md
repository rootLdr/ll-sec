# Firebase

As regras (`firestore.rules`, `storage.rules`, `database.rules.json`) são a única
tranca real: o SDK do cliente fala direto com o banco, sem passar por servidor seu.

## Os dois padrões que aparecem em quase todo projeto gerado por IA

```javascript
// 1) porta aberta — qualquer um, sem login
match /{document=**} {
  allow read, write: if true;
}

// 2) "só logado" — todo usuário vê os dados de todos
match /{document=**} {
  allow read, write: if request.auth != null;
}
```

O primeiro é **Crítico**. O segundo é **Alto**: criar conta é grátis, então
"autenticado" não é um filtro — falta comparar o dono do documento:

```javascript
match /pedidos/{id} {
  allow read, update, delete: if request.auth.uid == resource.data.userId;
  allow create: if request.auth.uid == request.resource.data.userId;
}
```

Repare na diferença entre `resource` (documento como está no banco) e
`request.resource` (como o cliente quer gravar). Usar só `resource` no `create`
não funciona, e usar só `request.resource` no `update` deixa o usuário reivindicar
documento alheio.

## Data de expiração

O template do console gera regras com prazo:

```javascript
allow read, write: if request.time < timestamp.date(2026, 1, 1);
```

Antes da data, é porta aberta. Depois, o app quebra inteiro. Registre como
**Crítico** se a data ainda não passou.

## Outros pontos

- **Admin SDK** (`firebase-admin`, `serviceAccountKey.json`) ignora todas as
  regras. Só no servidor; o JSON de service account nunca no repositório.
- **API key do Firebase** (`AIza...`) no cliente é normal e não é segredo — não
  reporte como vazamento. O que protege é a regra, não a chave. Se o scanner
  acusar, rebaixe para Informativo explicando isso.
- **App Check** ausente permite abuso da API por fora do seu app (custo).
- **Storage**: regra separada. Upload liberado + arquivo servido no seu domínio =
  XSS hospedado por você.
- **Cloud Functions** HTTP sem verificação de token são endpoints públicos.
