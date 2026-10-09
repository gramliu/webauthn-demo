import { spawn } from 'node:child_process';

const commands = [
  spawn('go', ['run', '.'], { cwd: new URL('../backend', import.meta.url), stdio: 'inherit' }),
  spawn('npm', ['run', 'dev'], { cwd: new URL('../web', import.meta.url), stdio: 'inherit' }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const process of commands) process.kill('SIGTERM');
  setTimeout(() => process.exit(code), 100).unref();
}
for (const child of commands) {
  child.on('error', err => { console.error(err.message); stop(1); });
  child.on('exit', code => { if (!stopping) stop(code || 0); });
}
process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
