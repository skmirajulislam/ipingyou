import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

async function testInject() {
  const homedir = os.homedir();
  const sshDir = path.join(homedir, '.ssh');
  const authKeysPath = path.join(sshDir, 'authorized_keys');
  console.log('Homedir:', homedir);

  // Let's check permissions
  const stat = await fs.promises.stat(homedir);
  console.log('Homedir mode:', stat.mode.toString(8));

  const sshStat = await fs.promises.stat(sshDir).catch(() => null);
  console.log('SSH dir mode:', sshStat ? sshStat.mode.toString(8) : 'Not found');

  const authStat = await fs.promises.stat(authKeysPath).catch(() => null);
  console.log('Auth keys mode:', authStat ? authStat.mode.toString(8) : 'Not found');
}

testInject();
