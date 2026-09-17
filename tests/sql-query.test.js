import test from "node:test";
import assert from "node:assert/strict";
import { validateSelectQuery, validatePlaceholderPositions } from "../src/shared/sql-query.js";

test("read queries preserve CASE, aggregate clauses, literals and comments", () => {
  const query = "WITH 1 AS n SELECT CASE WHEN n = 1 THEN 'DROP; --' ELSE 'other' END AS Result, count(ID) AS attempts FROM `events` GROUP BY Result HAVING attempts > 1 ORDER BY attempts DESC LIMIT 500 OFFSET 10";
  assert.equal(validateSelectQuery(`${query};`), query);
  assert.equal(validateSelectQuery(`-- comment\n${query}`), `-- comment\n${query}`);
  for (const invalid of ["DROP TABLE events", "SELECT 1; SELECT 2", "WITH x AS (DELETE FROM events) SELECT x", "SELECT 1 INTO OUTFILE 'x'", "SELECT 'unterminated", "SELECT 1 FORMAT CSV"]) assert.throws(() => validateSelectQuery(invalid));
});
test("placeholder positions cannot turn values into SQL fragments", () => {
  for (const valid of ["Field = '${Field}'", "Field = ${Field}", "Message LIKE concat('%', ${Field}, '%')", "${@host} AND Type = 1"]) validatePlaceholderPositions(valid);
  for (const invalid of ["Field = '%${Field}%'", "`Field${Field}` = 1", "${Field}suffix = 1", "'x' -- ${Field}", "'x' /* ${Field} */", '"${Field}" = 1']) assert.throws(() => validatePlaceholderPositions(invalid));
});

test("SQL preparation removes comments and whitespace outside literals only", async () => {
  const { compactSql, prepareSelectQuery } = await import("../src/shared/sql-query.js");
  const sql = "-- заголовок\nSELECT\n  'два  пробела -- текст /* текст */' AS value,\n  CASE /* пояснение */ WHEN X >= 2 THEN 'a\\'--b' ELSE 'line\n  two' END AS result\nFROM `events` -- хвост\nWHERE User = '${User}'\nORDER BY Timestamp DESC; -- конец";
  const prepared = prepareSelectQuery(sql);
  assert.equal(prepared, "SELECT 'два  пробела -- текст /* текст */' AS value, CASE WHEN X >= 2 THEN 'a\\'--b' ELSE 'line\n  two' END AS result FROM `events` WHERE User = '${User}' ORDER BY Timestamp DESC");
  assert.equal(compactSql("SELECT 1/* split */+2"), "SELECT 1 +2");
  assert.throws(() => compactSql("SELECT 1 /* незакрыт"), /Незакрытый комментарий/);
  assert.throws(() => prepareSelectQuery("SELECT 1; -- спрятано\nDELETE FROM events"));
});
