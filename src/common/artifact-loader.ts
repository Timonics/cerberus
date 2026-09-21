import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Read an artifact (OpenAPI YAML, GraphQL SDL, etc.) preferring
 * `dist/<name>` and falling back to `src/<name>`.
 *
 * Why both paths?
 *
 * In production (CI deploys), the build script copies these artifacts
 * to `dist/` so they're served from the same root as the compiled JS.
 * That keeps the runtime read deterministic.
 *
 * In dev (`npm run start:dev`), `nest start --watch` is configured with
 * `deleteOutDir: true`, so the watcher wipes `dist/` on every rebuild.
 * Our copy scripts run ONCE at boot, but a TS rebuild mid-session
 * removes the copies. Falling back to `src/<name>` means the Scalar UI
 * still works regardless of when the watcher last wiped.
 *
 * Order is intentional:
 *   1. dist/<name>  — preferred (matches the prod path)
 *   2. src/<name>   — dev fallback (works without a build step)
 *
 * If neither exists, throws. Callers can wrap in try/catch if they
 * want a soft fallback (e.g. log a warning instead of crashing).
 */
export function readArtifact(distName: string, srcName?: string): string {
  const distPath = join(process.cwd(), 'dist', distName);
  if (existsSync(distPath)) {
    return readFileSync(distPath, 'utf8');
  }
  const fallbackName = srcName ?? distName;
  const srcPath = join(process.cwd(), 'src', fallbackName);
  if (existsSync(srcPath)) {
    return readFileSync(srcPath, 'utf8');
  }
  throw new Error(
    `Artifact not found: tried ${distPath} and ${srcPath}. ` +
      'Run "npm run build" to generate the dist/ artifacts.',
  );
}
