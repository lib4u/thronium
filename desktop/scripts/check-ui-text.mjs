// User-facing JSX text must belong to a catalog. Protocols and examples are explicit exceptions.
import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '..');
const allow = JSON.parse(fs.readFileSync(path.join(root, 'locales/technical-literals.json'), 'utf8'));
const parsed = ts.parseJsonConfigFileContent(ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile).config, ts.sys, root);
const violations = [];
for (const file of parsed.fileNames.filter(file => file.endsWith('.tsx'))) {
  const source = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  function visit(node) {
    let value;
    if (ts.isJsxText(node)) value = node.text.replace(/\s+/g, ' ').trim();
    if (ts.isJsxAttribute(node) && ['title', 'placeholder', 'aria-label', 'alt'].includes(node.name.getText()) && node.initializer && ts.isStringLiteralLike(node.initializer)) value = node.initializer.text;
    if (value && /[A-Za-zА-Яа-я]/.test(value) && !allow.some(entry => entry.file === path.relative(root, file) && entry.value === value)) violations.push(`${path.relative(root, file)}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1}: ${value}`);
    ts.forEachChild(node, visit);
  }
  visit(source);
}
if (violations.length) throw Error('Move UI text to locales or justify a technical literal:\n' + violations.join('\n'));
console.log('JSX text matches the catalog / explicit technical allowlist.');
