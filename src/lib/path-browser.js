import { execa } from 'execa';
import chalk from 'chalk';
import inquirer from 'inquirer';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { buildSshArgs, formatRemoteCd } from './ssh.js';

class RemoteDirectoryError extends Error {
  constructor(message, remoteDir, stderr = '') {
    super(message);
    this.name = 'RemoteDirectoryError';
    this.remoteDir = remoteDir;
    this.stderr = stderr;
  }
}

function expandLocalPath(inputPath) {
  const trimmed = inputPath.trim();
  if (trimmed === '~') return os.homedir();
  if (trimmed.startsWith(`~${path.sep}`) || trimmed.startsWith('~/')) {
    return path.join(os.homedir(), trimmed.slice(2));
  }
  return trimmed;
}

export async function promptLocalFileBrowser(startPath = process.cwd()) {
  let items;
  try {
    items = fs.readdirSync(startPath, { withFileTypes: true });
  } catch (err) {
    console.log(chalk.yellow(`  ⚠️  Cannot open ${startPath}: ${err.message}`));
    const parent = path.dirname(startPath);
    return promptLocalFileBrowser(parent === startPath ? process.cwd() : parent);
  }

  const choices = [
    { name: '📁 .. (Up a directory)', value: 'UP' },
    { name: '✅ SELECT CURRENT DIRECTORY', value: 'SELECT_DIR' },
    new inquirer.Separator(),
    ...items.map(item => ({
      name: `${item.isDirectory() ? '📁' : '📄'} ${item.name}`,
      value: path.join(startPath, item.name),
      isDir: item.isDirectory()
    }))
  ];

  const { selection } = await inquirer.prompt([{
    type: 'list',
    name: 'selection',
    message: `Browse local files [${startPath}]:`,
    choices,
    pageSize: 15
  }]);

  if (selection === 'UP') {
    return promptLocalFileBrowser(path.dirname(startPath));
  }
  if (selection === 'SELECT_DIR') {
    return startPath;
  }

  let stat;
  try {
    stat = fs.statSync(selection);
  } catch (err) {
    console.log(chalk.yellow(`  ⚠️  Cannot access ${selection}: ${err.message}`));
    return promptLocalFileBrowser(startPath);
  }
  if (stat.isDirectory()) {
    const { action } = await inquirer.prompt([{
      type: 'list',
      name: 'action',
      message: `Selected Folder: ${path.basename(selection)}`,
      choices: [
        { name: '📂 Open Folder', value: 'open' },
        { name: '✅ Select this Folder for Transfer', value: 'select' }
      ]
    }]);

    if (action === 'open') return promptLocalFileBrowser(selection);
    return selection;
  }

  return selection;
}

export async function promptLocalPath(label, browserStart = process.cwd()) {
  const { pathMode } = await inquirer.prompt([{
    type: 'list',
    name: 'pathMode',
    message: `How do you want to select the ${label}?`,
    choices: [
      { name: '⌨️  Type path manually', value: 'manual' },
      { name: '🔍 Browse local files interactively', value: 'browse' }
    ]
  }]);

  if (pathMode === 'browse') {
    return promptLocalFileBrowser(browserStart);
  }

  const { localPath } = await inquirer.prompt([{
    type: 'input',
    name: 'localPath',
    message: `Local ${label} path:`,
    validate: v => v.trim().length > 0 || 'Required',
  }]);
  return expandLocalPath(localPath);
}

async function listRemoteDirectory(username, hostname, privateKeyPath, remoteDir) {
  const cdTarget = formatRemoteCd(remoteDir);
  const cdCommand = cdTarget ? `cd ${cdTarget}` : 'cd';
  const command = `${cdCommand} && printf '__SECURELINK_PWD__%s\\n' "$PWD" && ls -1Ap`;
  const sshArgs = buildSshArgs(hostname, privateKeyPath);
  sshArgs.push(`${username}@${hostname}`, command);

  const result = await execa('ssh', sshArgs, {
    stdio: ['inherit', 'pipe', 'pipe'],
    reject: false,
  });

  if (result.exitCode !== 0) {
    const detail = result.stderr.trim() || `ssh exited with code ${result.exitCode}`;
    throw new RemoteDirectoryError(`Remote directory listing failed: ${detail}`, remoteDir, result.stderr);
  }

  const lines = result.stdout.split(/\r?\n/).filter(Boolean);
  const pwdLine = lines.find(line => line.startsWith('__SECURELINK_PWD__'));
  const pwd = pwdLine ? pwdLine.replace('__SECURELINK_PWD__', '') : remoteDir || '~';

  const entries = lines
    .filter(line => !line.startsWith('__SECURELINK_PWD__'))
    .filter(line => !line.endsWith('@') && !line.endsWith('|') && !line.endsWith('='))
    .map(line => {
      const isDir = line.endsWith('/');
      const name = isDir ? line.slice(0, -1) : line;
      return {
        name,
        isDir,
        path: pwd === '/' ? `/${name}` : `${pwd}/${name}`,
      };
    });

  return { pwd, entries };
}

export async function promptRemotePath(username, hostname, privateKeyPath, purpose) {
  const browseLabel = purpose === 'source'
    ? 'Browse host files interactively'
    : 'Browse host folders interactively';

  const manualLabel = purpose === 'source'
    ? 'Type host file/folder path manually'
    : 'Type host destination path manually';

  const { remoteMode } = await inquirer.prompt([{
    type: 'list',
    name: 'remoteMode',
    message: purpose === 'source'
      ? 'How do you want to select the host file/folder to download?'
      : 'How do you want to select the host destination?',
    choices: [
      { name: `⌨️  ${manualLabel}`, value: 'manual' },
      { name: `🔍 ${browseLabel}`, value: 'browse' }
    ]
  }]);

  if (remoteMode === 'manual') {
    const { remotePath } = await inquirer.prompt([{
      type: 'input',
      name: 'remotePath',
      message: purpose === 'source'
        ? `Host file/folder path (relative to ${username}'s home or absolute):`
        : `Host destination path (relative to ${username}'s home or absolute):`,
      validate: v => v.trim().length > 0 || 'Required',
    }]);
    return remotePath.trim();
  }

  let currentDir = '~';
  while (true) {
    let listing;
    try {
      listing = await listRemoteDirectory(username, hostname, privateKeyPath, currentDir);
    } catch (err) {
      console.log(chalk.yellow(`  ⚠️  Could not browse host files: ${err.message}`));
      if (/Operation not permitted/i.test(err.stderr || err.message)) {
        console.log(chalk.dim('     macOS privacy blocked this SSH session from listing that folder.'));
        console.log(chalk.dim('     On the host, allow Full Disk Access for sshd/Remote Login, or choose a non-protected folder.'));
      }

      const parentDir = currentDir === '/' ? '/' : path.posix.dirname(currentDir);
      if (parentDir && parentDir !== currentDir) {
        console.log(chalk.dim(`     Returning to ${parentDir}.`));
        currentDir = parentDir;
        continue;
      }

      console.log(chalk.dim('     Falling back to manual host path entry.'));
      const { remotePath } = await inquirer.prompt([{
        type: 'input',
        name: 'remotePath',
        message: purpose === 'source' ? 'Host file/folder path:' : 'Host destination path:',
        validate: v => v.trim().length > 0 || 'Required',
      }]);
      return remotePath.trim();
    }

    currentDir = listing.pwd;
    const choices = [
      { name: '📁 .. (Up a directory)', value: { action: 'up' } },
      { name: purpose === 'destination' ? '✅ SELECT CURRENT DIRECTORY' : '✅ Select this Folder for Transfer', value: { action: 'select', path: currentDir } },
      new inquirer.Separator(),
      ...listing.entries.map(item => ({
        name: `${item.isDir ? '📁' : '📄'} ${item.name}`,
        value: { action: item.isDir ? 'open_or_select' : 'select', path: item.path, name: item.name }
      }))
    ];

    const { selection } = await inquirer.prompt([{
      type: 'list',
      name: 'selection',
      message: `Browse host files [${currentDir}]:`,
      choices,
      pageSize: 15
    }]);

    if (selection.action === 'up') {
      currentDir = currentDir === '/' ? '/' : path.posix.dirname(currentDir);
    } else if (selection.action === 'select') {
      return selection.path;
    } else if (selection.action === 'open_or_select') {
      const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: `Selected Host Folder: ${selection.name}`,
        choices: purpose === 'source'
          ? [
              { name: '📂 Open Folder', value: 'open' },
              { name: '✅ Select this Folder for Transfer', value: 'select' }
            ]
          : [
              { name: '📂 Open Folder', value: 'open' },
              { name: '✅ Use this Folder as Destination', value: 'select' }
            ]
      }]);

      if (action === 'open') currentDir = selection.path;
      else return selection.path;
    }
  }
}
