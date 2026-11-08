import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { hashPassword } from '../apps/api/src/security.mjs';

const terminal = createInterface({ input: stdin, output: stdout });

function askHidden(question) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    throw new Error('Abre Terminal de macOS y ejecuta este archivo directamente para ocultar la contraseña al escribirla.');
  }
  stdout.write(question);
  stdin.setRawMode(true);
  stdin.setEncoding('utf8');
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = (error) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdout.write('\n');
      error ? reject(error) : resolve(value);
    };
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\u0003') return finish(new Error('Cancelado.'));
        if (char === '\r' || char === '\n') return finish();
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else if (char >= ' ') value += char;
      }
    };
    stdin.on('data', onData);
  });
}

try {
  const email = (await terminal.question('Correo con el que inicias sesión en Barrio: ')).trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('Escribe un correo válido.');
  const password = await askHidden('Nueva contraseña (12 a 128 caracteres; no se mostrará): ');
  if (password.length < 12 || password.length > 128) throw new Error('La contraseña debe tener entre 12 y 128 caracteres.');
  const confirmation = await askHidden('Escribe la contraseña otra vez para confirmar: ');
  if (password !== confirmation) throw new Error('Las contraseñas no coinciden. No se generó el SQL.');
  const { salt, hash } = await hashPassword(password);
  const quote = (value) => value.replaceAll("'", "''");
  console.log('\nCopia el bloque SQL siguiente directamente en Supabase → SQL Editor. No lo compartas por chat.\n');
  console.log(`begin;\nwith updated as (\n  update public.barrio_users\n  set password_hash = decode('${hash.toString('hex')}', 'hex'),\n      password_salt = decode('${salt.toString('hex')}', 'hex')\n  where lower(email) = lower('${quote(email)}') and active = true\n  returning id\n)\nselect count(*) as cuentas_actualizadas from updated;\ncommit;`);
  console.log('\nLa contraseña nueva no se imprimió ni se guardó en un archivo.');
} finally {
  terminal.close();
}
