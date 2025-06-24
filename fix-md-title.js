// fix_md_title.js（ESM版）
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// 解决 __dirname 在 ESM 中不存在的问题
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const docsDir = path.join(__dirname, 'src/content/docs');

function fixMarkdownFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');

  if (content.startsWith('---') && /title:/i.test(content.split('---')[1])) return;

  const lines = content.split('\n');
  let titleLine = lines.find(line => line.startsWith('# '));
  let title = titleLine ? titleLine.replace('# ', '').trim() : path.basename(filePath, '.md');

  const frontmatter = `---\ntitle: ${title}\n---\n\n`;

  if (content.startsWith('---')) {
    const parts = content.split('---');
    parts[1] = `\ntitle: ${title}\n` + parts[1];
    fs.writeFileSync(filePath, parts.join('---'));
  } else {
    fs.writeFileSync(filePath, frontmatter + content);
  }

  console.log(`✅ Fixed: ${filePath}`);
}

function walk(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (let entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath);
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      fixMarkdownFile(fullPath);
    }
  }
}

walk(docsDir);