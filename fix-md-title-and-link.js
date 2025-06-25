// fix_md_links_to_projects.js（ESM）
// ✅ 替换 Markdown 中所有以 projects 开头的相对路径为 /projects/... 绝对路径（去掉 .md/.mdx 后缀）
// ✅ 自动补全 frontmatter 中缺失的 title 字段
// ✅ 对 projects/*/index.md 提取 # xxx Rules 的 xxx 作为 title

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const docsDir = path.join(__dirname, 'src/content/docs');

// 匹配项目型链接：projects/xx/yy.md 或 ./projects/xx.md
const projectLinkRegex = /\[([^\]]+)\]\((?:\.{0,2}\/)?projects\/([^\)\s]+?)(?:\.mdx?|\/)?\)/g;

// 判断是否是 projects 下二级 index.md
function isProjectsIndex(filepath) {
  const rel = path.relative(docsDir, filepath).replace(/\\/g, '/'); // 兼容 Windows
  return /^projects\/[^/]+\/index\.md$/.test(rel);
}

// 从 "# xxx Rules" 中提取 "xxx"
function extractTitleFromH1(line) {
  return line.replace(/^#\s*/, '').replace(/\s+Rules$/, '').trim();
}

function fixMarkdownFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf-8');
  let updated = false;

  const lines = content.split('\n');

  // === 1️⃣ 生成 title ===
  const hasFrontmatter = content.startsWith('---');
  let title = path.basename(filePath, '.md');

  if (isProjectsIndex(filePath)) {
    // 从第一行 # xxx Rules 中提取 title
    const h1 = lines.find(line => line.startsWith('# '));
    if (h1) {
      title = extractTitleFromH1(h1);
    } else {
      // fallback，用目录名
      title = path.basename(path.dirname(filePath));
    }
  } else {
    const h1 = lines.find(line => line.startsWith('# '));
    if (h1) {
      title = h1.replace('# ', '').trim();
    }
  }

  // === 2️⃣ 添加/补充 frontmatter ===
  if (hasFrontmatter) {
    const parts = content.split('---');
    const front = parts[1];
    if (!/title\s*:/i.test(front)) {
      parts[1] = `\ntitle: ${title}\n` + front.trim() + '\n';
      content = parts.join('---');
      updated = true;
    }
  } else {
    const frontmatter = `---\ntitle: ${title}\n---\n\n`;
    content = frontmatter + content;
    updated = true;
  }

  // === 3️⃣ 替换链接为 /projects/...，去掉扩展名 ===
  const fixedContent = content.replace(projectLinkRegex, (match, text, linkPath) => {
    const clean = linkPath.replace(/\.mdx?$/, '');
    return `[${text}](/projects/${clean})`;
  });

  if (fixedContent !== content) {
    content = fixedContent;
    updated = true;
  }

  if (updated) {
    fs.writeFileSync(filePath, content, 'utf-8');
    console.log(`✅ Fixed: ${filePath}`);
  }
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