export default function Painel({ user }) {
  if (user.role === "admin") {
    return <BotaoApagarTudo />;
  }
  return <p>Sem acesso</p>;
}
