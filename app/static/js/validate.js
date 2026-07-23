// Frontend validation (OWASP Top 10 2024 Proactive Control C3).
// Backend re-validates independently; this is only a first line of defense.
function validateForm() {
  var input = document.getElementById("search_term");
  var pattern = /^[A-Za-z0-9 ]{3,50}$/;
  if (!pattern.test(input.value)) {
    input.value = "";
    alert("Invalid input. Please try again.");
    return false;
  }
  return true;
}
