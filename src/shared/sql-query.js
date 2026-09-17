// Lexical checks only. KUMA remains the authority for SQL syntax and supported functions.
function lexSql(sql) {
  const tokens = [];
  const pattern = /\s+|--[^\r\n]*|\/\*[\s\S]*?(?:\*\/|$)|'(?:\\[\s\S]|''|[^'\\])*'|"(?:\\[\s\S]|""|[^"\\])*"|`(?:\\[\s\S]|``|[^`\\])*`|[A-Za-z_][A-Za-z0-9_]*|[\s\S]/g;
  for (const match of sql.matchAll(pattern)) {
    const value = match[0];
    if (value.startsWith("/*") && !value.endsWith("*/")) throw new TypeError("Незакрытый комментарий в SQL");
    if (["'", '"', "`"].includes(value)) throw new TypeError("Незакрытая кавычка в SQL");
    tokens.push({ value, start: match.index, end: match.index + value.length, spacing: /^\s|^--|^\/\*/.test(value) });
  }
  return tokens;
}

function sqlTokens(sql) { return lexSql(sql).filter(token => !token.spacing); }

// Whitespace and comments are changed only outside quoted strings/identifiers.
export function compactSql(input) {
  let result = "", space = false;
  for (const token of lexSql(String(input ?? ""))) {
    if (token.spacing) { space = true; continue; }
    if (space && result) result += " ";
    result += token.value; space = false;
  }
  return result;
}

export function prepareSelectQuery(input) { return compactSql(validateSelectQuery(input)); }

export function validateSelectQuery(input) {
  const sql = String(input ?? "").trim();
  if (!sql || sql.length > 64000 || sql.includes("\0")) throw new TypeError("SQL-запрос должен содержать от 1 до 64000 символов");
  const tokens = sqlTokens(sql);
  if (tokens.at(-1)?.value === ";") tokens.pop();
  const words = tokens.map(token => token.value.toUpperCase());
  if (!["SELECT", "WITH"].includes(words[0]) || !words.includes("SELECT") || words.includes(";")) {
    throw new TypeError("Разрешён один SQL-запрос SELECT (в том числе WITH … SELECT)");
  }
  if (words.some(word => /^(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|ATTACH|DETACH|RENAME|GRANT|REVOKE|OPTIMIZE|SYSTEM|KILL|INTO|OUTFILE|FORMAT|SETTINGS)$/.test(word))) {
    throw new TypeError("Разрешён только поиск SELECT, без изменения данных, FORMAT, SETTINGS и вывода в файл");
  }
  // Drop only the optional terminal delimiter; retain comments, literals and formatting.
  const delimiter = sqlTokens(sql).find(token => token.value === ";");
  return delimiter ? sql.slice(0, delimiter.start) + sql.slice(delimiter.end) : sql;
}

export function validatePlaceholderPositions(template) {
  const tokens = sqlTokens(template);
  for (const match of template.matchAll(/\$\{(@?[A-Za-z][A-Za-z0-9_]*)\}/g)) {
    const token = tokens.find(item => item.start <= match.index && item.end > match.index);
    // Only a whole value is substituted: never part of an identifier, literal or comment.
    if (!token || token.value.startsWith('"') || token.value.startsWith("`") ||
        token.value.startsWith("'") && token.value !== `'${match[0]}'` ||
        /[A-Za-z0-9_$]/.test(template[match.index - 1] || "") ||
        /[A-Za-z0-9_$]/.test(template[match.index + match[0].length] || "")) {
      throw new TypeError("Подстановка должна быть отдельным значением, а не частью строки, имени поля или комментария");
    }
  }
}
