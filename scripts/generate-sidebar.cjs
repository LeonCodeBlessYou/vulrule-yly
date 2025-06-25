// generate-sidebar.cjs
const fs = require('fs');
const path = require('path');

const docsRoot = path.join(__dirname, '../src/content/docs');
const outputFile = path.join(__dirname, '../src/sidebar.generated.ts');

// 替换空格为短横线的 slugify 函数
function slugify(str) {
  return str.replace(/\s+/g, '-').toLowerCase();
}

// 构建 sidebar 节点（递归目录结构）
function buildSidebar(dirPath, baseUrl = '') {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const items = [];

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const nameWithoutExt = entry.name.replace(/\.md$/, '');
    const slugLabel = nameWithoutExt;
    const slugLink = slugify(nameWithoutExt);

    if (entry.isDirectory()) {
      const subItems = buildSidebar(fullPath, `${baseUrl}/${slugify(entry.name)}`);
      if (subItems.length > 0) {
        items.push({
          label: entry.name,
          items: subItems,
        });
      }
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      const isIndex = nameWithoutExt.toLowerCase() === 'index';
      items.push({
        label: slugLabel,
        link: isIndex ? baseUrl || '/' : `${baseUrl}/${slugLink}`,
      });
    }
  }

  return items;
}

// 生成完整 sidebar 树
function generateSidebar() {
  const sidebar = [];

  const topLevelDirs = fs.readdirSync(docsRoot, { withFileTypes: true });

  for (const dirent of topLevelDirs) {
    if (dirent.isDirectory()) {
      const sectionPath = path.join(docsRoot, dirent.name);
      const sectionItems = buildSidebar(sectionPath, `/${slugify(dirent.name)}`);
      if (sectionItems.length > 0) {
        sidebar.push({
          label: dirent.name,
          items: sectionItems,
        });
      }
    }
  }

  return sidebar;
}

// 写入 sidebar.generated.ts
function writeSidebarFile(sidebar) {
  const content =
    `// THIS FILE IS AUTO-GENERATED. DO NOT EDIT MANUALLY.\n\n` +
    `export const sidebar = ${JSON.stringify(sidebar, null, 2)};\n`;

  fs.writeFileSync(outputFile, content, 'utf-8');
  console.log(`✅ Sidebar written to ${outputFile}`);
}

// 主流程
const sidebar = generateSidebar();
writeSidebarFile(sidebar);