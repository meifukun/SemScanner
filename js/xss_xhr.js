
xss_array = []

function xss(data) {
  try {
    // 使用简单的 GET 请求把 payload 发送到本机 listener（端口 9091）
    var xhr = new XMLHttpRequest();
    var url = "http://127.0.0.1:9091/?data=" + encodeURIComponent(data);
    xhr.open("GET", url, true);
    xhr.send();
  } catch (e) {
    // 退回到本地数组记录（备份）
    try { xss_array.push(data); } catch (e2) {}
  }
}
