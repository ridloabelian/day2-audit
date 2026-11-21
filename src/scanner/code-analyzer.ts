import type { ScannedFile } from '../types.js';

export type CommentLang = 'js' | 'py' | 'sql';

export interface CallExpressionMatch {
  callee: string;
  argsText: string;
  startIndex: number;
  endIndex: number;
  startLine: number;
  endLine: number;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'ALL';

export interface HttpRoute {
  method: HttpMethod;
  routePath: string;
  handlerBody: string;
  startLine: number;
  framework: 'nextjs-app' | 'nextjs-pages' | 'node-api' | 'cloudflare-workers' | 'fastapi';
}

/**
 * Compute 1-based line number for a character offset in source text.
 */
export function offsetToLine(code: string, offset: number): number {
  let line = 1;
  const limit = Math.min(offset, code.length);
  for (let i = 0; i < limit; i++) {
    if (code.charCodeAt(i) === 10) {
      line++;
    }
  }
  return line;
}

/**
 * Get trimmed single-line snippet at a 1-based line number.
 */
export function getLineSnippet(lines: string[], line: number): string | undefined {
  const raw = lines[line - 1];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  return trimmed.length > 140 ? `${trimmed.slice(0, 137)}...` : trimmed;
}

/**
 * Strip comments while preserving exact string literals and newline offsets
 * so line numbers remain 1:1 with the original source file.
 */
export function stripCommentsKeepLines(code: string, lang: CommentLang): string {
  const out: string[] = [];
  const len = code.length;
  let i = 0;

  while (i < len) {
    const ch = code[i]!;
    const next = code[i + 1];

    // Triple-quoted strings in Python
    if (
      lang === 'py' &&
      (ch === '"' || ch === "'") &&
      code[i + 1] === ch &&
      code[i + 2] === ch
    ) {
      const quote = ch;
      out.push(quote, quote, quote);
      i += 3;
      while (i < len) {
        const c = code[i]!;
        if (c === '\\' && i + 1 < len) {
          out.push(c, code[i + 1]!);
          i += 2;
          continue;
        }
        out.push(c);
        if (c === quote && code[i + 1] === quote && code[i + 2] === quote) {
          out.push(quote, quote);
          i += 3;
          break;
        }
        i++;
      }
      continue;
    }

    // String literals (JS single/double/template, SQL single/double, Python single/double)
    const isStringQuote =
      ch === "'" || ch === '"' || (lang === 'js' && ch === '`');
    if (isStringQuote) {
      const quote = ch;
      out.push(quote);
      i++;
      while (i < len) {
        const c = code[i]!;
        if (c === '\\' && i + 1 < len) {
          out.push(c, code[i + 1]!);
          i += 2;
          continue;
        }
        if (lang === 'sql' && quote === "'" && c === "'" && code[i + 1] === "'") {
          out.push("''");
          i += 2;
          continue;
        }
        out.push(c);
        if (c === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    // Line comments
    if (
      (lang === 'js' && ch === '/' && next === '/') ||
      (lang === 'py' && ch === '#') ||
      (lang === 'sql' && ch === '-' && next === '-')
    ) {
      while (i < len && code[i] !== '\n') {
        out.push(' ');
        i++;
      }
      continue;
    }

    // Block comments (JS & SQL)
    if ((lang === 'js' || lang === 'sql') && ch === '/' && next === '*') {
      out.push(' ', ' ');
      i += 2;
      while (i < len) {
        const c = code[i]!;
        if (c === '*' && code[i + 1] === '/') {
          out.push(' ', ' ');
          i += 2;
          break;
        }
        out.push(c === '\n' ? '\n' : ' ');
        i++;
      }
      continue;
    }

    out.push(ch);
    i++;
  }

  return out.join('');
}

function advancePastString(code: string, start: number): number {
  const quote = code[start]!;
  let i = start + 1;
  while (i < code.length) {
    const c = code[i]!;
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === quote) {
      return i + 1;
    }
    i++;
  }
  return code.length;
}

/**
 * Extract balanced parentheses starting at `openParenIndex`.
 */
export function extractBalancedParens(
  code: string,
  openParenIndex: number,
): { body: string; endIndex: number } {
  if (code[openParenIndex] !== '(') {
    return { body: '', endIndex: openParenIndex };
  }
  let depth = 1;
  let i = openParenIndex + 1;
  while (i < code.length && depth > 0) {
    const ch = code[i]!;
    if (ch === "'" || ch === '"' || ch === '`') {
      i = advancePastString(code, i);
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    i++;
  }
  const endIndex = i;
  const body = code.slice(openParenIndex + 1, Math.max(openParenIndex + 1, endIndex - 1));
  return { body, endIndex };
}

/**
 * Extract balanced curly brace block starting at `openBraceIndex`.
 */
export function extractBalancedBlock(
  code: string,
  openBraceIndex: number,
): { body: string; endIndex: number } {
  if (code[openBraceIndex] !== '{') {
    return { body: '', endIndex: openBraceIndex };
  }
  let depth = 1;
  let i = openBraceIndex + 1;
  while (i < code.length && depth > 0) {
    const ch = code[i]!;
    if (ch === "'" || ch === '"' || ch === '`') {
      i = advancePastString(code, i);
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    i++;
  }
  const endIndex = i;
  const body = code.slice(openBraceIndex + 1, Math.max(openBraceIndex + 1, endIndex - 1));
  return { body, endIndex };
}

/**
 * Find function/method call expressions matching `calleeRegex` (must match the
 * callee immediately preceding `(`, or optionally including trailing `\(`).
 */
export function extractCallExpressions(
  strippedCode: string,
  calleeRegex: RegExp,
): CallExpressionMatch[] {
  const flags = calleeRegex.flags.includes('g')
    ? calleeRegex.flags
    : `${calleeRegex.flags}g`;
  const re = new RegExp(calleeRegex.source, flags);
  const results: CallExpressionMatch[] = [];

  let match: RegExpExecArray | null;
  while ((match = re.exec(strippedCode)) !== null) {
    const matchText = match[0];
    let openParenIdx: number;
    if (matchText.endsWith('(')) {
      openParenIdx = match.index + matchText.length - 1;
    } else {
      let cursor = match.index + matchText.length;
      while (cursor < strippedCode.length && /\s/.test(strippedCode[cursor]!)) {
        cursor++;
      }
      if (strippedCode[cursor] !== '(') continue;
      openParenIdx = cursor;
    }

    const { body, endIndex } = extractBalancedParens(strippedCode, openParenIdx);
    const startLine = offsetToLine(strippedCode, match.index);
    const endLine = offsetToLine(strippedCode, endIndex);
    results.push({
      callee: matchText.replace(/\($/, '').trim(),
      argsText: body,
      startIndex: match.index,
      endIndex,
      startLine,
      endLine,
    });
  }

  return results;
}

/**
 * Extract Python indented block starting after a line ending in `:`.
 */
export function extractPythonIndentedBlock(
  code: string,
  headerLineEndIndex: number,
): { body: string; endIndex: number } {
  const nlIdx = code.indexOf('\n', headerLineEndIndex);
  if (nlIdx === -1) return { body: '', endIndex: code.length };

  const rest = code.slice(nlIdx + 1);
  const lines = rest.split('\n');
  let baseIndent: number | null = null;
  const collected: string[] = [];
  let offset = nlIdx + 1;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') {
      collected.push(line);
      offset += line.length + 1;
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (baseIndent === null) {
      baseIndent = indent;
      if (baseIndent === 0) break;
    } else if (indent < baseIndent) {
      break;
    }
    collected.push(line);
    offset += line.length + 1;
  }

  return {
    body: collected.join('\n'),
    endIndex: Math.min(code.length, offset),
  };
}

function nextJsAppRoutePath(relPath: string): string {
  const m = /(?:^|\/)app\/(.+)\/route\.[jt]sx?$/.exec(relPath);
  if (!m) return '/';
  const raw = m[1]!
    .split('/')
    .filter((seg) => !(seg.startsWith('(') && seg.endsWith(')')))
    .join('/');
  return `/${raw}`;
}

function nextJsPagesRoutePath(relPath: string): string {
  const m = /(?:^|\/)pages(\/api\/.+?)(?:\/index)?\.[jt]sx?$/.exec(relPath);
  return m ? m[1]! : '/api';
}

function extractFunctionBodyAfterParams(
  stripped: string,
  fromIndex: number,
): string {
  // Scan ahead for `{` (skipping TS return type annotations like `: Promise<Response>`)
  let i = fromIndex;
  let parenDepth = 0;
  let angleDepth = 0;
  while (i < stripped.length) {
    const ch = stripped[i]!;
    if (ch === "'" || ch === '"' || ch === '`') {
      i = advancePastString(stripped, i);
      continue;
    }
    if (ch === '(') parenDepth++;
    else if (ch === ')' && parenDepth > 0) parenDepth--;
    else if (ch === '<' && parenDepth === 0) angleDepth++;
    else if (ch === '>' && parenDepth === 0 && angleDepth > 0) angleDepth--;
    else if (ch === '{' && parenDepth === 0) {
      return extractBalancedBlock(stripped, i).body;
    }
    i++;
  }
  return '';
}

/**
 * Extract HTTP route handlers from Next.js, Express/Fastify/Hono, Cloudflare Workers, or FastAPI files.
 */
export function extractHttpRoutes(
  file: ScannedFile,
  isWorkerEntry = false,
): HttpRoute[] {
  const routes: HttpRoute[] = [];
  const rel = file.relPath;

  if (file.ext === '.py') {
    const stripped = stripCommentsKeepLines(file.content, 'py');
    const pyRouteRe =
      /@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*(['"])([^'"]+)\2[\s\S]*?\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\(([\s\S]*?)\)\s*:/gi;
    let m: RegExpExecArray | null;
    while ((m = pyRouteRe.exec(stripped)) !== null) {
      const method = m[1]!.toUpperCase() as HttpMethod;
      const routePath = m[3]!;
      const params = m[4] ?? '';
      const startLine = offsetToLine(stripped, m.index);
      const { body } = extractPythonIndentedBlock(stripped, m.index + m[0].length);
      routes.push({
        method,
        routePath,
        handlerBody: `${params}\n${body}`,
        startLine,
        framework: 'fastapi',
      });
    }
    return routes;
  }

  if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(file.ext)) {
    return routes;
  }

  const stripped = stripCommentsKeepLines(file.content, 'js');

  // 1. Next.js App Router: app/**/route.ts
  if (/(?:^|\/)app\/.+\/route\.[jt]sx?$/.test(rel)) {
    const routePath = nextJsAppRoutePath(rel);
    const fnRe =
      /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = fnRe.exec(stripped)) !== null) {
      const method = m[1] as HttpMethod;
      const startLine = offsetToLine(stripped, m.index);
      const paren = extractBalancedParens(stripped, m.index + m[0].length - 1);
      const body = extractFunctionBodyAfterParams(stripped, paren.endIndex);
      routes.push({
        method,
        routePath,
        handlerBody: `${paren.body}\n${body}`,
        startLine,
        framework: 'nextjs-app',
      });
    }

    const constRe =
      /export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=\s*/g;
    while ((m = constRe.exec(stripped)) !== null) {
      const method = m[1] as HttpMethod;
      const startLine = offsetToLine(stripped, m.index);
      const rest = stripped.slice(m.index + m[0].length);
      const arrowOrBrace = rest.indexOf('{');
      const body =
        arrowOrBrace !== -1
          ? extractBalancedBlock(rest, arrowOrBrace).body
          : rest.slice(0, 400);
      routes.push({
        method,
        routePath,
        handlerBody: body,
        startLine,
        framework: 'nextjs-app',
      });
    }
    return routes;
  }

  // 2. Next.js Pages API Router: pages/api/**/*.ts
  if (/(?:^|\/)pages\/api\/.+\.[jt]sx?$/.test(rel)) {
    const routePath = nextJsPagesRoutePath(rel);
    const defaultRe = /export\s+default\s+(?:async\s+)?(?:function\s*\w*\s*\(|(?:async\s*)?\()/;
    const m = defaultRe.exec(stripped);
    const startLine = m ? offsetToLine(stripped, m.index) : 1;
    const body = stripped;
    const mutatingMethods: HttpMethod[] = [];
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
      if (new RegExp(`['"]${method}['"]`).test(stripped)) {
        mutatingMethods.push(method);
      }
    }
    if (mutatingMethods.length > 0) {
      for (const method of mutatingMethods) {
        routes.push({
          method,
          routePath,
          handlerBody: body,
          startLine,
          framework: 'nextjs-pages',
        });
      }
    } else {
      routes.push({
        method: 'ALL',
        routePath,
        handlerBody: body,
        startLine,
        framework: 'nextjs-pages',
      });
    }
    return routes;
  }

  // 3. Express / Fastify / Hono routes
  const nodeRouteCalls = extractCallExpressions(
    stripped,
    /\b(?:app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(/i,
  );
  for (const call of nodeRouteCalls) {
    const headMatch = /^\s*(['"`])([^'"`]+)\1/.exec(call.argsText);
    if (!headMatch) continue;
    const routePath = headMatch[2]!;
    const methodMatch = /\.(get|post|put|patch|delete|all)$/i.exec(call.callee);
    const method = (methodMatch?.[1]?.toUpperCase() ?? 'ALL') as HttpMethod;
    routes.push({
      method,
      routePath,
      handlerBody: call.argsText,
      startLine: call.startLine,
      framework: 'node-api',
    });
  }

  // 4. Cloudflare Workers fetch() handler
  if (isWorkerEntry && routes.length === 0) {
    const fetchRe = /\b(?:async\s+)?fetch\s*(?::\s*async\s*)?\(\s*(\w+)/;
    const m = fetchRe.exec(stripped);
    if (m) {
      const startLine = offsetToLine(stripped, m.index);
      const body = extractFunctionBodyAfterParams(stripped, m.index);
      const mutating = /\b(?:POST|PUT|PATCH|DELETE)\b/.test(body)
        ? ('POST' as const)
        : ('ALL' as const);
      routes.push({
        method: mutating,
        routePath: '/',
        handlerBody: body,
        startLine,
        framework: 'cloudflare-workers',
      });
    }
  }

  return routes;
}
