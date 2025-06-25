const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.resolve('src/content/docs');
const OUTPUT_FILE = path.resolve('sidebar.generated.ts');

function getAllMarkdownFiles(dirPath) {
  let results = [];
  const files = fs.readdirSync(dirPath);

  files.forEach((file) => {
    const fullPath = path.join(dirPath, file);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      results = results.concat(getAllMarkdownFiles(fullPath));
    } else if (file.endsWith('.md') || file.endsWith('.mdx')) {
      results.push(fullPath);
    }
  });

  return results;
}

function formatLink(filePath) {
  const relative = path.relative(DOCS_DIR, filePath).replace(/\\/g, '/');
  return '/' + relative.replace(/\.mdx?$/, '');
}

function formatLabel(filePath) {
  const base = path.basename(filePath, path.extname(filePath));
  return base.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const files = getAllMarkdownFiles(DOCS_DIR);

const groups = {};

for (const file of files) {
  const relative = path.relative(DOCS_DIR, file);
  const parts = relative.split(path.sep);
  const group = parts.length > 1 ? parts[0] : 'Root';
  if (!groups[group]) groups[group] = [];

  groups[group].push({
    label: formatLabel(file),
    link: formatLink(file),
  });
}

let output = '// 自动生成的 sidebar 配置，请复制到 astro.config.ts 中使用\n\n';
output += 'export const sidebar = [\n';

for (const [group, items] of Object.entries(groups)) {
  output += `  {\n    label: '${group}',\n    items: [\n`;
  for (const item of items) {
    output += `      { label: '${item.label}', link: '${item.link}' },\n`;
  }
  output += '    ]\n  },\n';
}

output += '];\n';

fs.writeFileSync(OUTPUT_FILE, output);
console.log(`✅ Sidebar 配置已写入：${OUTPUT_FILE}`);