// Loaded only in an isolated run. Report lookups to the existing relay and
// complete them with ENOTFOUND. The relay never resolves these names.
const dns = require('node:dns');
const net = require('node:net');

const relay = new URL(process.env.VEIL_TELL_DNS_RELAY);
const lookup = dns.lookup;
dns.lookup = function (host, options, callback) {
  const complete = typeof options === 'function' ? options : callback;
  if (typeof complete !== 'function' || typeof host !== 'string' ||
      host.length > 254 || !/^[a-z0-9.-]+$/i.test(host) ||
      !host.includes('.') || net.isIP(host)) {
    return lookup.apply(this, arguments);
  }
  let proxy;
  try {
    proxy = new URL(process.env.HTTPS_PROXY);
  } catch {
    proxy = relay;
  }
  const credentials = Buffer.from(
    `veil:${proxy.password && /^[a-z0-9_~.-]+$/i.test(proxy.password) ? proxy.password : relay.password}`,
  ).toString('base64');
  const socket = net.connect(Number(relay.port), '127.0.0.1');
  let finished = false;
  function fail() {
    if (finished) return;
    finished = true;
    socket.destroy();
    const error = Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), {
      code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: host,
    });
    complete(error);
  }
  socket.setTimeout(2000);
  socket.once('timeout', fail);
  socket.once('error', fail);
  socket.once('close', fail);
  socket.once('data', fail);
  socket.once('connect', () => socket.write(
    `VEIL-DNS ${host} HTTP/1.1\r\nProxy-Authorization: Basic ${credentials}\r\n\r\n`,
  ));
};

dns.promises.lookup = function (host, options) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, options, (error, address, family) => {
      if (error) reject(error);
      else resolve(Array.isArray(address) ? address : {address, family});
    });
  });
};

require("node:module").syncBuiltinESMExports();
