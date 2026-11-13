import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, watch, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const registryHost = 'registry.test';
const blockedHost = 'blocked.test';
const registry = `https://${registryHost}`;
const macos = process.platform === 'darwin';
const directDenied = macos ? 'EPERM' : 'ENETUNREACH';
const runtime = dirname(dirname(process.execPath));
const source = fileURLToPath(import.meta.url);
const version = '1.0.0';
const UNKNOWN_EXIT = 20;
const RELAY_STOP_EXIT = 125;

async function listen(server, endpoint, host) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => socket.destroy());
    socket.once('close', () => sockets.delete(socket));
  });
  const ready = once(server, 'listening');
  server.listen(endpoint, host);
  await ready;
  return {
    address: server.address(),
    close() {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

function bridge(client, upstream) {
  upstream.on('error', () => client.destroy());
  client.once('close', () => upstream.destroy());
  upstream.once('close', () => client.destroy());
  client.pipe(upstream).pipe(client);
}

function connectProxy(registryAddress, blockedAddress, restrict, decisions, explicitDeny = false) {
  const proxy = http.createServer((_, response) => response.writeHead(405).end());
  proxy.on('connect', (request, client, head) => {
    const authority = request.url;
    const address = authority === `${registryHost}:443` ? registryAddress
      : authority === `${blockedHost}:443` && !restrict ? blockedAddress : undefined;
    const reason = address ? (restrict ? 'allow_rule' : 'open')
      : explicitDeny && authority === `${blockedHost}:443` ? 'explicit_deny' : 'unknown_destination';
    decisions.push({ authority, result: address ? 'allow' : 'deny', reason, dial: Boolean(address) });
    if (!address) {
      client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    const upstream = net.createConnection({ host: address.address, port: address.port });
    upstream.once('error', () => client.destroy());
    upstream.once('connect', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      bridge(client, upstream);
    });
  });
  return proxy;
}

function makePackage(root, name, withProbe) {
  const build = join(root, name);
  const contents = join(build, 'package');
  mkdirSync(contents, { recursive: true });
  const manifest = { name, version };
  if (withProbe) {
    manifest.scripts = { postinstall: 'node postinstall.cjs' };
    copyFileSync(new URL('./postinstall.cjs', import.meta.url), join(contents, 'postinstall.cjs'));
  }
  writeFileSync(join(contents, 'package.json'), JSON.stringify(manifest));
  writeFileSync(join(contents, 'installed.txt'), `${name}\n`);
  execFileSync('tar', ['-czf', 'package.tgz', 'package'], { cwd: build });
  const tarball = readFileSync(join(build, 'package.tgz'));
  const path = `/${name}/-/${name}-${version}.tgz`;
  const dist = {
    tarball: `${registry}${path}`,
    integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}`,
  };
  return {
    name, tarball, path,
    packument: { name, 'dist-tags': { latest: version }, versions: { [version]: { ...manifest, dist } } },
  };
}

function npmInstall(directory, proxyPort, receiverAddress, trial, isolation = 'none') {
  const proxy = `http://127.0.0.1:${proxyPort}`;
  const npm = join(runtime, 'lib/node_modules/npm/bin/npm-cli.js');
  const command = [process.execPath, npm, 'install'];
  if (isolation === 'linux') {
    command.unshift('/usr/bin/python3', '/target.py', '--pipes');
  } else if (isolation === 'macos') {
    const profile = [
      '(version 1)',
      '(allow default)',
      '(deny network*)',
      `(allow network-outbound (remote tcp4 "localhost:${proxyPort}"))`,
    ].join('\n');
    command.unshift('/usr/bin/sandbox-exec', '-p', profile);
  }
  const [binary, ...args] = command;
  return runChild(binary, args, {
    cwd: directory,
    env: {
      PATH: `${runtime}/bin:/usr/bin:/bin`,
      HOME: directory,
      npm_config_userconfig: join(directory, 'user.npmrc'),
      npm_config_globalconfig: join(directory, 'global.npmrc'),
      npm_config_cache: join(directory, 'cache'),
      npm_config_registry: registry,
      npm_config_https_proxy: proxy,
      npm_config_cafile: join(directory, 'registry.crt'),
      npm_config_strict_ssl: 'true',
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
      npm_config_fetch_retries: '0',
      npm_config_foreground_scripts: 'true',
      LAB_PROXY: proxy,
      LAB_RECEIVER: receiverAddress,
      LAB_TRIAL: trial,
      LAB_TRIAL_DIR: directory,
    },
  });
}

async function runChild(binary, args, options) {
  const child = spawn(binary, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (data) => { output += data; });
  child.stderr.on('data', (data) => { output += data; });
  const [exitCode, signal] = await once(child, 'close');
  process.stdout.write(output);
  return { exitCode, signal, output };
}

async function isolatedInstall(bwrap, directory, proxySocket, receiverAddress, trial) {
  const args = [
    '--unshare-user', '--unshare-net', '--unshare-pid', '--die-with-parent',
    '--new-session', '--cap-drop', 'ALL', '--clearenv',
    '--dev', '/dev', '--proc', '/proc',
    '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
    '--ro-bind', '/bin', '/bin',
  ];
  if (existsSync('/lib64')) args.push('--ro-bind', '/lib64', '/lib64');
  args.push(
    '--ro-bind', runtime, '/runtime',
    '--ro-bind', source, '/harness.mjs',
    '--ro-bind', fileURLToPath(new URL('./target.py', import.meta.url)), '/target.py',
    '--ro-bind', proxySocket, '/proxy.sock',
    '--bind', directory, '/trial', '--chdir', '/trial',
    '--', '/runtime/bin/node', '/harness.mjs', 'relay', receiverAddress, trial,
  );
  return runChild(bwrap, args);
}

function relayLifetime(server, listener, directory, stopEnabled) {
  const stopRequest = join(directory, 'stop-relay');
  let stopping = false;
  let stopped = false;
  const watcher = stopEnabled ? watch(directory, (_event, filename) => {
    if (stopping || filename !== 'stop-relay' || !existsSync(stopRequest)) return;
    stopping = true;
    server.once('close', () => {
      stopped = true;
      console.log('relay event=stopped');
      writeFileSync(join(directory, 'relay-stopped'), '');
    });
    listener.close();
  }) : undefined;
  return {
    get stopped() { return stopped; },
    close() {
      watcher?.close();
      if (!stopping) listener.close();
    },
  };
}

async function relay(receiverAddress, trial) {
  const server = net.createServer((client) => bridge(client, net.createConnection('/proxy.sock')));
  const listener = await listen(server, 0, '127.0.0.1');
  const lifetime = relayLifetime(server, listener, '/trial', trial === 'relay-stop');
  try {
    const child = await npmInstall('/trial', listener.address.port, receiverAddress, trial, 'linux');
    console.log(`npm exit=${child.exitCode}`);
    return lifetime.stopped ? RELAY_STOP_EXIT : (child.exitCode ?? 1);
  } finally {
    lifetime.close();
  }
}

async function supervise(config) {
  const decisions = [];
  const proxy = connectProxy(config.registryAddress, config.blockedAddress, true, decisions, config.explicitDeny);
  const listener = await listen(proxy, config.endpoint, macos ? '127.0.0.1' : undefined);
  const stopTrial = config.trial === 'relay-stop';
  const lifetime = relayLifetime(proxy, listener, config.directory, macos && stopTrial);
  try {
    const child = macos
      ? await npmInstall(config.directory, listener.address.port, config.receiverAddress, config.trial, 'macos')
      : await isolatedInstall(config.bwrap, config.directory, config.endpoint,
        config.receiverAddress, config.trial);
    if (macos) console.log(`npm exit=${child.exitCode}`);
    const linuxRelayStopped = !macos && stopTrial && child.exitCode === RELAY_STOP_EXIT;
    const stopped = lifetime.stopped || linuxRelayStopped;
    const unknown = decisions.some(({ reason }) => reason === 'unknown_destination');
    let exitCode = child.exitCode ?? 1;
    let reason = exitCode === 0 ? 'completed' : 'child_failed';
    if (stopped) {
      reason = 'relay_stopped';
      exitCode = RELAY_STOP_EXIT;
    } else if (unknown && config.failOnUnknown) {
      reason = 'unknown_destination';
      exitCode = UNKNOWN_EXIT;
    }
    const report = {
      schema_version: 1,
      backend: 'isolated',
      mode: 'restrict',
      isolation: stopped || child.exitCode === 0 ? 'applied' : 'unconfirmed',
      coverage: {
        proxy: 'http_connect_requests',
        direct_attempt_destinations: 'not_observed',
        proxy_capture: stopped ? 'until_relay_stopped' : 'while_running',
      },
      child_status: { exit_code: linuxRelayStopped ? null : child.exitCode, signal: child.signal },
      run_status: { exit_code: exitCode, reason },
      destinations: decisions.map(({ authority, result, reason: decisionReason, dial }) => {
        const [host, port] = authority.split(':');
        return { host, port: Number(port), decision: result, reason: decisionReason, dial };
      }),
    };
    writeFileSync(config.report, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    return exitCode;
  } finally {
    lifetime.close();
  }
}

async function run(bwrap, ip) {
  console.log(`platform=${process.platform} uid=${process.getuid()}`);
  const root = mkdtempSync('/tmp/veil-tell-npm-');
  const npmVersion = JSON.parse(readFileSync(join(runtime, 'lib/node_modules/npm/package.json'), 'utf8')).version;
  console.log(`fixture_dir=${root} node=${process.version} npm=${npmVersion}`);
  const cert = join(root, 'registry.crt');
  const key = join(root, 'registry.key');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', `/CN=${registryHost}`, '-addext', `subjectAltName=DNS:${registryHost}`,
    '-keyout', key, '-out', cert,
  ], { stdio: 'pipe' });
  const plain = makePackage(root, 'veil-egress-plain', false);
  const probe = makePackage(root, 'veil-egress-probe', true);
  const registryRequests = [];
  const receives = [];
  const registryServer = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) },
    (request, response) => {
      registryRequests.push(`${request.method} ${request.url}`);
      const pkg = [plain, probe].find((fixture) => request.url === `/${fixture.name}`
        || request.url === fixture.path);
      if (!pkg || request.method !== 'GET') {
        response.writeHead(404).end();
      } else if (request.url === pkg.path) {
        response.writeHead(200, { 'content-type': 'application/octet-stream' }).end(pkg.tarball);
      } else {
        response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(pkg.packument));
      }
    });
  const receiverServer = net.createServer((socket) => {
    const record = { token: '' };
    receives.push(record);
    socket.setEncoding('utf8');
    socket.on('data', (data) => {
      record.token += data;
      if (record.token.endsWith('\n')) socket.end(`ACK ${record.token}`);
    });
  });
  const allowed = await listen(registryServer, 0, ip);
  const blocked = await listen(receiverServer, 0, ip);
  console.log(`receivers registry=${ip}:${allowed.address.port} unregistered=${ip}:${blocked.address.port}`);
  const receiverAddress = `http://${ip}:${blocked.address.port}`;

  const trials = [
    { name: 'plain-isolated', pkg: plain, restrict: true, isolated: true, tokens: [] },
    { name: 'open', pkg: probe, restrict: false, isolated: false, tokens: ['connect', 'direct'],
      connect: 'ack', direct: 'ack' },
    { name: 'rules', pkg: probe, restrict: true, isolated: false, tokens: ['direct'],
      connect: '403', direct: 'ack' },
    { name: 'isolated', pkg: probe, restrict: true, isolated: true, tokens: [],
      connect: '403', direct: directDenied },
    { name: 'ci-unknown', pkg: probe, restrict: true, isolated: true, tokens: [],
      connect: '403', direct: directDenied, exitCode: UNKNOWN_EXIT, reason: 'unknown_destination' },
    { name: 'ci-known', pkg: probe, restrict: true, isolated: true, tokens: [],
      connect: '403', direct: directDenied, exitCode: 0, reason: 'completed', explicitDeny: true },
    { name: 'relay-stop', pkg: probe, restrict: true, isolated: true, tokens: [],
      connect: 'ECONNREFUSED', direct: directDenied, exitCode: RELAY_STOP_EXIT, reason: 'relay_stopped' },
  ];
  try {
    for (const trial of trials) {
      const directory = join(root, trial.name);
      mkdirSync(directory);
      writeFileSync(join(directory, 'user.npmrc'), '');
      writeFileSync(join(directory, 'global.npmrc'), '');
      copyFileSync(cert, join(directory, 'registry.crt'));
      writeFileSync(join(directory, 'package.json'), JSON.stringify({
        name: 'veil-egress-test-project', version, private: true,
        dependencies: { [trial.pkg.name]: version },
      }));
      const decisions = [];
      // Put the endpoint outside the writable project, and mount only the socket in the sandbox.
      const unixProxy = trial.isolated && !macos;
      const endpoint = unixProxy ? `${directory}.sock` : 0;
      const supervised = trial.exitCode !== undefined;
      const listener = supervised ? undefined : await listen(
        connectProxy(allowed.address, blocked.address, trial.restrict, decisions),
        endpoint, unixProxy ? undefined : '127.0.0.1',
      );
      const requestStart = registryRequests.length;
      const receiveStart = receives.length;
      console.log(`trial=${trial.name} policy=${trial.restrict} isolated=${trial.isolated}`);
      try {
        const reportPath = join(root, `${trial.name}.json`);
        let child;
        if (supervised) {
          const config = {
            bwrap, directory, endpoint, receiverAddress, trial: trial.name, report: reportPath,
            registryAddress: allowed.address, blockedAddress: blocked.address,
            failOnUnknown: trial.name.startsWith('ci-'), explicitDeny: trial.explicitDeny,
          };
          child = await runChild(process.execPath, [source, 'supervise', JSON.stringify(config)]);
        } else if (unixProxy) {
          child = await isolatedInstall(bwrap, directory, endpoint, receiverAddress, trial.name);
        } else {
          const isolation = trial.isolated ? 'macos' : 'none';
          child = await npmInstall(directory, listener.address.port, receiverAddress, trial.name, isolation);
        }
        assert.equal(child.exitCode, trial.exitCode ?? 0);
        const report = supervised ? JSON.parse(readFileSync(reportPath, 'utf8')) : undefined;
        if (report) {
          assert.deepEqual(report.run_status, { exit_code: trial.exitCode, reason: trial.reason });
          assert.equal(report.isolation, 'applied');
          assert.equal(report.coverage.proxy, 'http_connect_requests');
          assert.equal(report.coverage.direct_attempt_destinations, 'not_observed');
          assert(child.output.includes('npm exit=0\n'));
          if (trial.name === 'relay-stop') {
            const stoppedAt = child.output.indexOf('relay event=stopped\n');
            assert(stoppedAt >= 0 && stoppedAt < child.output.indexOf('probe attempt route=connect'));
            assert.equal(report.coverage.proxy_capture, 'until_relay_stopped');
            assert.equal(report.child_status.exit_code, macos ? 0 : null);
          } else {
            assert.equal(report.child_status.exit_code, 0);
            assert.equal(report.coverage.proxy_capture, 'while_running');
          }
          console.log(`supervisor trial=${trial.name} exit=${child.exitCode} json=${reportPath}`);
        }
        const observed = report ? report.destinations.map(({ host, port, decision, reason, dial }) => ({
          authority: `${host}:${port}`, result: decision, reason, dial,
        })) : decisions;
        const requests = registryRequests.slice(requestStart);
        const tokens = receives.slice(receiveStart).map((record) => record.token);
        console.log(`registry trial=${trial.name} requests=${JSON.stringify(requests)}`);
        console.log(`proxy trial=${trial.name} decisions=${JSON.stringify(observed)}`);
        console.log(`receiver trial=${trial.name} connections=${tokens.length} tokens=${JSON.stringify(tokens)}`);
        assert(requests.includes(`GET /${trial.pkg.name}`));
        assert(requests.includes(`GET ${trial.pkg.path}`));
        assert.equal(readFileSync(join(directory, 'node_modules', trial.pkg.name, 'installed.txt'), 'utf8'),
          `${trial.pkg.name}\n`);
        assert(observed.some((decision) => decision.authority === `${registryHost}:443`
          && decision.result === 'allow' && decision.dial));
        assert.deepEqual(tokens, trial.tokens.map((route) => `${trial.name}-${route}\n`));
        if (trial.pkg === probe) {
          assert(child.output.includes(`probe result route=connect result=${trial.connect}\n`));
          assert(child.output.includes(`probe result route=direct result=${trial.direct}\n`));
          const blocked = observed.filter(({ authority }) => authority === `${blockedHost}:443`);
          const reason = trial.explicitDeny ? 'explicit_deny' : trial.restrict ? 'unknown_destination' : 'open';
          assert.deepEqual(blocked, trial.name === 'relay-stop' ? [] : [{
            authority: `${blockedHost}:443`, result: trial.restrict ? 'deny' : 'allow', reason, dial: !trial.restrict,
          }]);
        }
      } finally {
        listener?.close();
      }
    }
    console.log(`PASS: ${trials.length} cold-cache npm installs, receiver evidence, relay-stop and CI exit/JSON checks`);
  } finally {
    blocked.close();
    allowed.close();
  }
}

const [mode, first, second] = process.argv.slice(2);
if (mode === 'macos' && process.platform === 'darwin') await run(undefined, '127.0.0.1');
else if (mode === 'run' && first && second && process.platform === 'linux') await run(first, second);
else if (mode === 'relay' && first && second) process.exitCode = await relay(first, second);
else if (mode === 'supervise' && first) process.exitCode = await supervise(JSON.parse(first));
else throw new Error('usage: node npm.mjs macos | run /absolute/path/to/bwrap LAB_IPV4');
