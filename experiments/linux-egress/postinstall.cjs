const net = require('node:net');
const assert = require('node:assert/strict');
const { writeFile, access } = require('node:fs/promises');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

function send(route) {
  const direct = route === 'direct';
  const token = `${process.env.LAB_TRIAL}-${route}`;
  const endpoint = new URL(direct ? process.env.LAB_RECEIVER : process.env.LAB_PROXY);
  console.log(`probe attempt route=${route} token=${token}`);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: endpoint.hostname, port: Number(endpoint.port) });
    let response = '';
    let sendToken = direct;
    socket.setTimeout(3000, () => socket.destroy(new Error(`${route} timed out`)));
    socket.once('connect', () => {
      socket.write(direct
        ? `${token}\n`
        : 'CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n');
    });
    socket.on('data', (data) => {
      response += data.toString();
      if (!sendToken && response.includes('\r\n\r\n')) {
        const end = response.indexOf('\r\n\r\n');
        const status = response.slice(0, end).split(' ')[1];
        if (status === '403') {
          resolve('403');
          socket.destroy();
          return;
        }
        if (status !== '200') {
          socket.destroy(new Error(`unexpected CONNECT status ${status}`));
          return;
        }
        sendToken = true;
        response = response.slice(end + 4);
        socket.write(`${token}\n`);
      }
      if (sendToken && response === `ACK ${token}\n`) {
        resolve('ack');
        socket.end();
      }
    });
    socket.once('error', (error) => {
      const directDenied = process.platform === 'darwin' ? 'EPERM' : 'ENETUNREACH';
      if (direct && error.code === directDenied) resolve(error.code);
      else if (!direct && process.env.LAB_TRIAL === 'relay-stop'
        && error.code === 'ECONNREFUSED') resolve(error.code);
      else reject(error);
    });
    socket.once('close', () => reject(new Error(`${route} closed before a result`)));
  }).then((result) => {
    console.log(`probe result route=${route} result=${result}`);
    return result;
  });
}

async function main() {
  assert(process.env.LAB_TRIAL);
  if (process.env.LAB_TRIAL === 'relay-stop') {
    const directory = process.env.LAB_TRIAL_DIR;
    await writeFile(join(directory, 'stop-relay'), '');
    const end = Date.now() + 3000;
    while (true) {
      try {
        await access(join(directory, 'relay-stopped'));
        break;
      } catch (error) {
        if (error.code !== 'ENOENT' || Date.now() >= end) throw error;
        await delay(10);
      }
    }
  }
  await send('connect');
  await send('direct');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
