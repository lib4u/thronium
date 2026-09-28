// The Thronium version lives in package.json. Tauri reads it from there; the
// crates, their lockfiles and package-lock.json repeat it because their tools
// require a literal, and build_core.py stamps it into the core.
//   node scripts/version.mjs --check   fail on any copy that differs
//   node scripts/version.mjs 1.2.3     write the version everywhere
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const write = (file, text) => fs.writeFileSync(path.join(root, file), text);
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

// Each copy: where it is, how to read it, how to replace it.
const manifest = (file) => ({
  file,
  pattern: /^(version = ")([^"]*)(")/m,
});
const locked = (file, name) => ({
  file,
  pattern: new RegExp(`(\\[\\[package\\]\\]\\nname = "${name}"\\nversion = ")([^"]*)(")`),
});
const copies = [
  manifest('engine/Cargo.toml'),
  manifest('src-tauri/Cargo.toml'),
  locked('engine/Cargo.lock', 'thronium-engine'),
  locked('src-tauri/Cargo.lock', 'thronium-desktop'),
  locked('src-tauri/Cargo.lock', 'thronium-engine'),
  {
    file: 'package-lock.json',
    pattern: /^(\{\n {2}"name": "thronium-desktop",\n {2}"version": ")([^"]*)(")/,
  },
  {
    file: 'package-lock.json',
    pattern: /(\n {4}"": \{\n {6}"name": "thronium-desktop",\n {6}"version": ")([^"]*)(")/,
  },
  // The subscription User-Agent the settings offer by default.
  {
    file: 'contracts/settings.catalog.json',
    pattern: /("id": "user_agent",\n\s*"label": "[^"]*",\n\s*"default": "Throne\/Thronium-)([^"]*)(")/,
  },
];

const source = JSON.parse(read('package.json')).version;
const argument = process.argv[2];
if (argument && argument !== '--check') {
  if (!semver.test(argument)) throw Error(`Not a semantic version: ${argument}`);
  const pkg = read('package.json');
  write('package.json', pkg.replace(/("version": ")[^"]*(")/, `$1${argument}$2`));
  for (const { file, pattern } of copies) {
    const text = read(file);
    if (!pattern.test(text)) throw Error(`Version not found in ${file}`);
    write(file, text.replace(pattern, `$1${argument}$3`));
  }
  console.log(`Version set to ${argument}. Regenerate contracts: npm run contracts:generate`);
} else {
  const problems = [];
  if (!semver.test(source)) problems.push(`package.json: ${source} is not a semantic version`);
  if (JSON.parse(read('src-tauri/tauri.conf.json')).version !== '../package.json')
    problems.push('src-tauri/tauri.conf.json: version must be "../package.json"');
  for (const { file, pattern } of copies) {
    const found = read(file).match(pattern);
    if (!found) problems.push(`${file}: version not found`);
    else if (found[2] !== source) problems.push(`${file}: ${found[2]} instead of ${source}`);
  }
  if (problems.length) throw Error(`Version copies differ from package.json:\n${problems.join('\n')}`);
  console.log(`Version ${source} everywhere.`);
}
