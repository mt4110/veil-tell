// The isolated backend reports covered lookups to the existing relay and
// returns ENOTFOUND. The relay never resolves these names.
const dns = require('node:dns');
const net = require('node:net');

const fs = require('node:fs');
const path = require('node:path');

// Yarn Berry runs its own shell. pnpm can also run a custom shell.
// Read its lifecycle context when a Node process starts, without replacing it.
function lifecycle() {
  const root = process.env.VEIL_TELL_NODE_ROOT;
  const event = process.env.npm_lifecycle_event;
  const claimed = process.env.npm_package_json;
  if (!root || (!claimed && process.env.VEIL_TELL_NODE_MANAGER !== 'yarn') || !/^[a-z0-9_.:-]{1,64}$/i.test(event || '')) return;
  let fd;
  try {
    const cwd = fs.realpathSync(process.cwd());
    const manifest = path.join(cwd, 'package.json');
    if (claimed && fs.realpathSync(claimed) !== manifest) return;
    const relative = path.relative(fs.realpathSync(root), cwd) || '.';
    if (relative === '..' || relative.startsWith('../') || relative.length > 500) return;
    fd = fs.openSync(manifest, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
    if (!fs.fstatSync(fd).isFile()) return;
    const buffer = Buffer.alloc(1024 * 1024 + 1);
    const length = fs.readSync(fd, buffer);
    if (length >= buffer.length) return;
    const pkg = JSON.parse(buffer.subarray(0, length));
    if (pkg.name !== process.env.npm_package_name || pkg.version !== process.env.npm_package_version ||
        typeof pkg.scripts?.[event] !== 'string' ||
        (!claimed && pkg.scripts[event] !== process.env.npm_lifecycle_script)) return;
    return {name: pkg.name, version: pkg.version, script: event, path: relative};
  } catch {
    return;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}
const packageContext = lifecycle();
if (packageContext) {
  const label = Buffer.from(JSON.stringify(packageContext)).toString('base64url');
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy',
    'npm_config_proxy', 'npm_config_https_proxy', 'NPM_CONFIG_PROXY', 'NPM_CONFIG_HTTPS_PROXY']) {
    const proxy = process.env[name];
    if (proxy?.startsWith('http://veil:')) {
      process.env[name] = proxy.replace(/^(http:\/\/veil:[a-z0-9_-]+)(?:~[^@]*)?@/i, `$1~${label}@`);
    }
  }
}
if (!process.env.VEIL_TELL_DNS_RELAY) return;
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
  const [claimedSecret, attribution] = proxy.password.split('~', 2);
  const label = claimedSecret === relay.password && /^[a-z0-9_-]{1,2048}$/i.test(attribution || '')
    ? `~${attribution}` : '';
  const credentials = Buffer.from(`veil:${relay.password}${label}`).toString('base64');
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
