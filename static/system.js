// change one drop-down menu's options based on another's selected option
function toggleSubType() {
  const planetType = document.getElementById("new_planet_type").value;
  const subTypeSelect = document.getElementById("new_planet_subtype");
  subTypeSelect.innerHTML = "";

  const options = {
    other: [
      "<option disabled selected>Subtype</option>",
      '<option value="asteroid">Asteroid</option>',
      '<option value="station">Station</option>',
    ],
    planet: [
      "<option disabled selected>Subtype</option>",
      '<option value="rocky planet">Rocky planet</option>',
      '<option value="gas giant">Gas giant</option>',
      '<option value="ice giant">Ice giant</option>',
    ],
    star: [
      "<option disabled selected>Subtype</option>",
      '<option value="main sequence star">Main sequence</option>',
      '<option value="giant star">Giant</option>',
      '<option value="dwarf star">Dwarf</option>',
      '<option value="weird star">Special</option>',
    ],
  };

  options[planetType].forEach((option) => {
    subTypeSelect.insertAdjacentHTML("beforeend", option);
  });
}

// make "population" input invisible when "Star" chosen as POI type
function togglePopulation() {
  var populationRow = document.getElementById("new_planet_population_row");
  var populationInput = document.getElementById("new_planet_population");
  var planetType = document.getElementById("new_planet_type");

  if (planetType.selectedOptions[0].value === "star") {
    populationRow.style.display = "none";
    populationInput.value = 0;
  } else {
    populationRow.style.display = "";
  }
}
