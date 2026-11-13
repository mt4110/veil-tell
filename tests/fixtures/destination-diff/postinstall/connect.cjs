const net = require("node:net");

const proxy = new URL(process.env.HTTPS_PROXY);
const auth = Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64");
const destination = "postinstall.local:443";
const socket = net.connect({ host: proxy.hostname, port: Number(proxy.port) });
let response = "";

socket.setTimeout(5000, () => socket.destroy(new Error("CONNECT timed out")));
socket.on("error", error => {
  console.error(error.message);
  process.exitCode = 1;
});
socket.on("connect", () => {
  socket.write(`CONNECT ${destination} HTTP/1.1\r\nHost: ${destination}\r\nProxy-Authorization: Basic ${auth}\r\n\r\n`);
});
socket.on("data", data => {
  response += data.toString("ascii");
  if (response.startsWith("HTTP/1.1 200 ") && response.includes("\r\n\r\n")) {
    socket.end("fixture-postinstall");
  }
});
socket.on("end", () => {
  if (!response.startsWith("HTTP/1.1 403 ") && !response.endsWith("ACK")) {
    console.error("Unexpected fixture proxy response");
    process.exitCode = 1;
  }
});
