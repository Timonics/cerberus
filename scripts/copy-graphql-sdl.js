const fs = require('fs');
const path = require('path');
const src = 'src/graphql/types';
const dst = 'dist/graphql/types';
fs.mkdirSync(dst, { recursive: true });
for (const e of fs.readdirSync(src)) {
  fs.copyFileSync(path.join(src, e), path.join(dst, e));
}
console.log('Copied ' + src + ' -> ' + dst);