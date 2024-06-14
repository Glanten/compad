// preload images
var down_arrow = new Image();
down_arrow.src = "static/icon-arrow-down.svg";

var up_arrow = new Image();
up_arrow.src = "static/icon-arrow-up.svg";

// open or close a named section (it should start closed)
function collapseSegment(segmentId, iconId) {
  var element = document.getElementById(segmentId);
  var icon = document.getElementById(iconId);
  if (element.style.display === "none") {
    element.style.display = "block";
    icon.src = up_arrow.src;
  } else {
    element.style.display = "none";
    icon.src = down_arrow.src;
  }
}
