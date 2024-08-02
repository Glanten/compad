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
      '<option value="rocky planet">Rocky Planet</option>',
      '<option value="gas giant">Gas Giant</option>',
      '<option value="ice giant">Ice Giant</option>',
    ],
    star: [
      "<option disabled selected>Subtype</option>",
      '<option value="giant star">Giant Star</option>',
      '<option value="dwarf star">Dwarf Star</option>',
      '<option value="normal star">Normal Star</option>',
    ],
  };

  options[planetType].forEach((option) => {
    subTypeSelect.insertAdjacentHTML("beforeend", option);
  });
}
