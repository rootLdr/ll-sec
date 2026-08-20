const isAdmin = localStorage.getItem("isAdmin") === "true";
if (isAdmin) {
  document.querySelector("#painel").style.display = "block";
}

function mostrarBusca() {
  const termo = document.querySelector("#q").value;
  document.querySelector("#resultado").innerHTML = "<h2>Resultados para " + termo + "</h2>";
}
