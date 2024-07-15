// remove "NPC Name" input from compad form when NPC not selected in drop-down box
function toggleNPCName() {
  var recipientSelect = document.getElementById("compose_recipient");
  var npcNameRow = document.getElementById("npc_name_row");

  if (recipientSelect.value === "NPC") {
    npcNameRow.style.display = "";
  } else {
    npcNameRow.style.display = "none";
  }
}

// initial check to ensure the correct state is set when the page loads
document.addEventListener("DOMContentLoaded", function () {
  toggleNPCName();
});
