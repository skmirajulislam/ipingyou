import { execa } from 'execa';

export async function openUrl(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error('Cannot open an invalid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.href.length > 4096) {
    throw new Error('Only HTTP(S) URLs can be opened');
  }

  const [command, args] = process.platform === 'darwin'
    ? ['open', [url.href]]
    : process.platform === 'win32'
      ? ['explorer.exe', [url.href]]
      : ['xdg-open', [url.href]];

  const result = await execa(command, args, {
    reject: false,
    stdio: 'ignore',
    timeout: 10000,
  });
  if (result.failed && result.exitCode !== 0) {
    throw new Error(`Could not open URL with ${command}`);
  }
}
