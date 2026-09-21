/**
 * Copy `src/openapi.yaml` to `dist/openapi.yaml` as part of the build.
 *
 * The Scalar middleware mounts at `/api-docs` (public) and serves the
 * file via `app.use()` (Express). To avoid a runtime disk read in
 * production, we copy the file at build time and read it from `dist/`.
 *
 * This mirrors `scripts/copy-graphql-sdl.js` for the GraphQL SDL files.
 */
const fs = require('node:fs');
const path = require('node:path');

const srcDir = path.resolve(__dirname, '..', 'src');
const distDir = path.resolve(__dirname, '..', 'dist');

const inputs = [
  { src: path.join(srcDir, 'openapi.yaml'), dest: path.join(distDir, 'openapi.yaml') },
  {
    src: path.join(srcDir, 'openapi-admin.yaml'),
    dest: path.join(distDir, 'openapi-admin.yaml'),
  },
];

let copied = 0;
for (const { src, dest } of inputs) {
  if (!fs.existsSync(src)) {
    console.warn(`[copy-openapi] source not found: ${src} — skipping`);
    continue;
  }
  if (!fs.existsSync(path.dirname(dest))) {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
  }
  fs.copyFileSync(src, dest);
  console.log(`[copy-openapi] copied ${src} -> ${dest}`);
  copied++;
}

if (copied === 0) {
  console.error('[copy-openapi] no files copied — Scalar will not be able to render');
  process.exit(1);
}
