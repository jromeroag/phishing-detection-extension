document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.replace("about:blank");
});
