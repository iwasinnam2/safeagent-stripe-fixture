#!/usr/bin/env node
// Independent JS serialization for the bounded fixture domain (no npm deps).
// stdin: JSON value; stdout: canonical JSON string plus SHA-256 as JSON.
"use strict";
const crypto = require("crypto");
const { stdin, stdout } = process;

function string(value) {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(++i);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new TypeError("lone surrogate");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError("lone surrogate");
    }
  }
  return JSON.stringify(value);
}

function serialize(obj) {
  if (obj === null) return "null";
  if (typeof obj === "boolean") return obj ? "true" : "false";
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) throw new TypeError("non-finite number");
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") return string(obj);
  if (Array.isArray(obj))
    return "[" + obj.map((v) => serialize(v)).join(",") + "]";
  const keys = Object.keys(obj).slice().sort(); // default == UTF-16 code-unit order (RFC 8785)
  return (
    "{" +
    keys.map((k) => string(k) + ":" + serialize(obj[k])).join(",") +
    "}"
  );
}

let data = "";
stdin.setEncoding("utf8");
stdin.on("data", (c) => (data += c));
stdin.on("end", () => {
  const obj = JSON.parse(data);
  const canonical = serialize(obj);
  const sha256 = crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
  stdout.write(JSON.stringify({ canonical, sha256 }) + "\n");
});
