import { execa } from 'execa';
import chalk from 'chalk';
import { createSpinner, tunnelSpinner } from '../mod/animations.js';
import { killProcessTree, trackPID, untrackPID } from '../mod/cleanup.js';

export async function spawnTunnelSupervised(targetUrl, onUrlGenerated) {
  let isShuttingDown = false;
  let activeChild = null;

  const loop = async () => {
    while (!isShuttingDown) {
      const spinner = createSpinner('Starting Cloudflare tunnel...', tunnelSpinner).start();

      await new Promise((resolve) => {
        activeChild = execa('cloudflared', ['tunnel', '--url', targetUrl], {
          reject: false,
          all: true,
          buffer: false,
        });

        trackPID(activeChild.pid);
        let resolved = false;

        activeChild.all.on('data', (chunk) => {
          const text = chunk.toString();
          const match = text.match(/https:\/\/[-0-9a-z]+\.trycloudflare\.com/);
          if (match && !resolved) {
            resolved = true;
            spinner.succeed(`Tunnel active: ${chalk.cyan(match[0])}`);
            onUrlGenerated(match[0]);
          }
        });

        activeChild.on('exit', (code) => {
          untrackPID(activeChild.pid);
          if (!resolved) {
            spinner.fail('Cloudflare tunnel exited before generating URL');
          } else if (!isShuttingDown) {
            console.log(chalk.yellow(`\n  ⚠️  Tunnel disconnected (code ${code}). Restarting...`));
          }
          resolve();
        });

        activeChild.on('error', (err) => {
          untrackPID(activeChild.pid);
          spinner.fail(`Tunnel error: ${err.message}`);
          resolve();
        });
      });

      if (!isShuttingDown) {
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  };

  loop();

  return {
    kill: () => {
      isShuttingDown = true;
      if (activeChild) {
        killProcessTree(activeChild.pid).finally(() => untrackPID(activeChild.pid));
      }
    }
  };
}
