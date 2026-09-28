import fs from 'node:fs';
import path from 'node:path';

const desktop = path.resolve(import.meta.dirname, '..');
const namespaces = [
  'common',
  'connection',
  'library',
  'profiles',
  'imports',
  'subscriptions',
  'routing',
  'settings',
  'diagnostics',
  'backups',
  'otp',
  'native',
  'errors',
];
// Interface languages come from one manifest; a language is added there and as a catalog folder.
const manifest = JSON.parse(fs.readFileSync(path.join(desktop, 'locales/languages.json'), 'utf8'));
const codes = manifest.languages.map((language) => language.code);
if (
  !codes.length ||
  codes[0] !== manifest.source ||
  new Set(codes).size !== codes.length ||
  codes.some((code) => !/^[a-z]{2,3}(?:-[A-Za-z0-9]+)*$/.test(code)) ||
  // The NSIS language the Windows installer shows it in (its "Language files").
  manifest.languages.some((language) => !/^[A-Za-z]+$/.test(language.installer ?? ''))
)
  throw Error('Invalid locales/languages.json');
const catalogs = Object.fromEntries(codes.map((code) => [code, {}]));
const placeholders = (value) => [...new Set(value.match(/\{\w+\}/g) || [])].sort();
for (const language of codes) {
  for (const namespace of namespaces) {
    const values = JSON.parse(
      fs.readFileSync(path.join(desktop, 'locales', language, namespace + '.json'), 'utf8'),
    );
    if (
      !values ||
      typeof values !== 'object' ||
      Array.isArray(values) ||
      Object.values(values).some((value) => typeof value !== 'string')
    )
      throw Error(`Invalid catalog: ${language}/${namespace}`);
    catalogs[language][namespace] = values;
  }
}
for (const namespace of namespaces) {
  const source = catalogs[manifest.source][namespace];
  for (const language of codes.slice(1)) {
    const target = catalogs[language][namespace];
    if (JSON.stringify(Object.keys(source).sort()) !== JSON.stringify(Object.keys(target).sort()))
      throw Error(`Locale keys differ: ${language}/${namespace}`);
    for (const key of Object.keys(source)) {
      if (JSON.stringify(placeholders(source[key])) !== JSON.stringify(placeholders(target[key])))
        throw Error(`Placeholders differ: ${language}/${namespace}.${key}`);
    }
  }
  for (const key of Object.keys(source)) {
    if (key.endsWith('_one')) {
      for (const category of ['few', 'many', 'other'])
        if (!(key.slice(0, -3) + category in source))
          throw Error(`Missing plural variant: ${namespace}.${key}`);
    }
  }
}
const settingsLanguage = JSON.parse(
  fs.readFileSync(path.join(desktop, 'contracts/settings.catalog.json'), 'utf8'),
).find((field) => field.id === 'language');
if (
  JSON.stringify([...settingsLanguage.options].sort()) !== JSON.stringify([...codes].sort()) ||
  !codes.includes(settingsLanguage.default)
)
  throw Error('contracts/settings.catalog.json language options must match locales/languages.json');
const imports = [],
  exports = Object.fromEntries(codes.map((code) => [code, []]));
const identifier = (code) => code.replace(/-(\w)/g, (_, c) => c.toUpperCase());
for (const language of codes)
  for (const namespace of namespaces) {
    const alias = identifier(language) + namespace[0].toUpperCase() + namespace.slice(1);
    imports.push(
      `import ${alias} from '../../../../locales/${language}/${namespace}.json' with { type: 'json' };`,
    );
    exports[language].push(`...qualify('${namespace}', ${alias})`);
  }
const typescript =
  '// Generated catalog imports; text belongs to desktop/locales.\n' +
  imports.join('\n') +
  `
function qualify<N extends string, T extends Record<string, string>>(namespace: N, values: T): { [K in keyof T as \`\${N}.\${K & string}\`]: T[K] } {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [\`\${namespace}.\${key}\`, value])) as { [K in keyof T as \`\${N}.\${K & string}\`]: T[K] };
}
` +
  codes.map((language) => `const ${identifier(language)} = {${exports[language].join(', ')}};`).join('\n') +
  `
export type MessageKey = keyof typeof ${identifier(manifest.source)};
export type Catalog = Readonly<Record<MessageKey, string>>;
export const sourceLanguage = ${JSON.stringify(manifest.source)};
export const languages = ${JSON.stringify(manifest.languages)} as const;
export type Language = (typeof languages)[number]['code'];
export const catalogs: Readonly<Record<Language, Catalog>> = { ${codes.map((code) => `${JSON.stringify(code)}: ${identifier(code)}`).join(', ')} };
`;
const keys = Object.keys(catalogs.en.native).sort();
const variant = (key) =>
  key
    .split('_')
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join('');
const rust =
  `// Generated from desktop/locales/languages.json and each native.json.\n#[rustfmt::skip]\npub const CATALOGS: &[(&str, &str)] = &[\n${codes.map((code) => `    (${JSON.stringify(code)}, include_str!("../../locales/${code}/native.json")),\n`).join('')}];\n` +
  '#[derive(Clone, Copy)]\n#[rustfmt::skip]\npub enum TextKey {\n' +
  // A `windows_` text belongs to the Windows native UI only; other builds
  // would report it unused, while the Windows build still does if it is.
  keys
    .map(
      (key) =>
        (key.startsWith('windows_')
          ? '    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]\n'
          : '') + `    ${variant(key)},\n`,
    )
    .join('') +
  "}\n#[rustfmt::skip]\nimpl TextKey { pub fn as_str(self) -> &'static str { match self {\n" +
  keys.map((key) => `    Self::${variant(key)} => ${JSON.stringify(key)},\n`).join('') +
  '} } }\n';
// Pages the Core serves to the browser read their texts from one generated script.
const dashboard = Object.fromEntries(
  codes.map((code) => [
    code,
    JSON.parse(fs.readFileSync(path.join(desktop, 'locales', code, 'dashboard.json'), 'utf8')),
  ]),
);
for (const code of codes.slice(1))
  if (
    JSON.stringify(Object.keys(dashboard[code]).sort()) !==
    JSON.stringify(Object.keys(dashboard[manifest.source]).sort())
  )
    throw Error(`Locale keys differ: ${code}/dashboard`);
const dashboardScript = `// Generated from desktop/locales/*/dashboard.json.\nconst THRONIUM_SOURCE_LANGUAGE = ${JSON.stringify(manifest.source)};\nconst THRONIUM_MESSAGES = ${JSON.stringify(dashboard)};\n`;
const outputs = {
  'src/shared/i18n/generated/catalogs.ts': typescript,
  'src-tauri/src/localization_keys.rs': rust,
  'engine/src/dashboard/messages.js': dashboardScript,
};
// The Windows installer offers the same languages, in manifest order.
{
  const file = path.join(desktop, 'src-tauri/tauri.windows.conf.json');
  const config = JSON.parse(fs.readFileSync(file, 'utf8'));
  const nsis = config.bundle.windows.nsis;
  nsis.languages = manifest.languages.map((language) => language.installer);
  nsis.displayLanguageSelector = nsis.languages.length > 1;
  const prettier = await import('prettier');
  outputs['src-tauri/tauri.windows.conf.json'] = await prettier.format(JSON.stringify(config), {
    ...(await prettier.resolveConfig(file)),
    filepath: file,
  });
}
for (const [name, text] of Object.entries(outputs)) {
  const file = path.join(desktop, name);
  if (process.argv.includes('--check')) {
    if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== text)
      throw Error(`Regenerate localization: ${name}`);
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  }
}
console.log(
  `Checked ${Object.values(catalogs[manifest.source]).reduce((count, values) => count + Object.keys(values).length, 0)} translation keys and ${keys.length} native keys.`,
);
