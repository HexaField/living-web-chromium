import { ChildProcess, spawn } from 'child_process';
import path from 'path';

let relayProcess: ChildProcess | null = null;

export async function startRelay(port = 4000): Promise<void> {
  if (relayProcess) return;

  const relayScript = path.resolve(
    __dirname,
    '../../../../w3c-living-web-proposals/examples/relay/src/index.ts'
  );

  relayProcess = spawn('npx', ['tsx', relayScript], {
    env: { ...process.env, PORT: String(port) },
    stdio: 'pipe',
  });

  // Wait for relay to be listening
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Relay startup timeout')), 10000);

    relayProcess!.stdout?.on('data', (data: Buffer) => {
      if (data.toString().includes('listening') || data.toString().includes(String(port))) {
        clearTimeout(timeout);
        resolve();
      }
    });

    relayProcess!.stderr?.on('data', (data: Buffer) => {
      console.error('[relay stderr]', data.toString());
    });

    relayProcess!.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    // Fallback: just wait a bit for it to start
    setTimeout(() => {
      clearTimeout(timeout);
      resolve();
    }, 3000);
  });
}

export async function stopRelay(): Promise<void> {
  if (relayProcess) {
    relayProcess.kill('SIGTERM');
    relayProcess = null;
  }
}
