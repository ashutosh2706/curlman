#!/usr/bin/env node
/**
 * CURLman Proxy Server (Node.js)
 * ─────────────────────────────
 * Forwards requests from the CURLman browser UI to any target URL,
 * bypassing browser CORS restrictions.
 *
 * Usage:
 *   node proxy.js                  runs on http://127.0.0.1:7474
 *   node proxy.js --port 9090      custom port
 *   node proxy.js --host 0.0.0.0   expose on LAN
 *
 * Requirements:
 *   npm install axios
 *
 * Build standalone binary (optional):
 *   npm install -g pkg
 *   pkg proxy.js --targets node18-win-x64,node18-linux-x64 --output proxy
 */

"use strict";

const http    = require("http");
const https   = require("https");
const url     = require("url");
const path    = require("path");

// ── Try to load axios, guide user if missing ─────────────────────
let axios;
try {
  axios = require("axios");
} catch {
  console.error("");
  console.error("  Missing dependency: axios");
  console.error("  Run:  npm install axios");
  console.error("");
  process.exit(1);
}

// ── CLI args ─────────────────────────────────────────────────────
const args = process.argv.slice(2);
const getArg = (flag, def) => {
  const i = args.indexOf(flag);
  return i !== -1 && args[i + 1] ? args[i + 1] : def;
};
const HOST = getArg("--host", "127.0.0.1");
const PORT = parseInt(getArg("--port", "7474"), 10);

// ── CORS headers added to every response ─────────────────────────
const CORS_HEADERS = {
  "Access-Control-Allow-Origin":      "*",
  "Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
  "Access-Control-Allow-Headers":     "*",
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Expose-Headers":    "*",
};

// Headers we strip before forwarding to the target
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade", "host",
]);

// Headers we strip from the target response before sending back
const STRIP_RESP = new Set([
  ...HOP_BY_HOP,
  "content-length",   // we set this ourselves after reading full body
  "content-encoding", // axios decodes gzip/br for us; raw length would be wrong
]);

// ── Helper: read full request body as Buffer ──────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data",  chunk => chunks.push(chunk));
    req.on("end",   ()    => resolve(Buffer.concat(chunks)));
    req.on("error", err   => reject(err));
  });
}

// ── Helper: send a plain JSON error response ──────────────────────
function sendError(res, code, message) {
  const body = JSON.stringify({ error: message });
  res.writeHead(code, {
    ...CORS_HEADERS,
    "Content-Type":   "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
  console.log(`  ERROR ${code}  ${message}`);
}

// ── Helper: send CORS preflight response ─────────────────────────
function sendPreflight(res) {
  res.writeHead(204, { ...CORS_HEADERS, "Content-Length": "0" });
  res.end();
}

// ── Helper: send health-check response ───────────────────────────
function sendPing(res) {
  const body = JSON.stringify({ status: "ok", server: "CURLman Proxy (Node.js)" });
  res.writeHead(200, {
    ...CORS_HEADERS,
    "Content-Type":   "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
  console.log(`  200  PING`);
}

// ── Core proxy handler ────────────────────────────────────────────
async function handleProxy(req, res) {
  const t0 = Date.now();

  // 1. Read and parse the JSON envelope from CURLman
  let envelope;
  try {
    const raw = await readBody(req);
    envelope  = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    return sendError(res, 400, `Bad envelope JSON: ${e.message}`);
  }

  const {
    url:       targetUrl   = "",
    method:    method      = "GET",
    headers:   reqHeaders  = {},
    bodyType:  bodyType    = "none",
    body:      bodyData    = null,
  } = envelope;

  if (!targetUrl) {
    return sendError(res, 400, "Missing 'url' in request envelope");
  }

  // 2. Build forwarding headers (strip hop-by-hop)
  const fwdHeaders = {};
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) {
      fwdHeaders[k] = v;
    }
  }

  // 3. Build the request body for axios
  let axiosData      = undefined;
  let axiosHeaders   = { ...fwdHeaders };

  const m = method.toUpperCase();

  if (!["GET", "HEAD"].includes(m) && bodyType !== "none") {

    if (bodyType === "json") {
      axiosData = bodyData || "";
      axiosHeaders["Content-Type"] = axiosHeaders["Content-Type"] || "application/json";

    } else if (bodyType === "form") {
      axiosData = bodyData || "";
      axiosHeaders["Content-Type"] = axiosHeaders["Content-Type"] || "application/x-www-form-urlencoded";

    } else if (bodyType === "text") {
      axiosData = bodyData || "";
      axiosHeaders["Content-Type"] = axiosHeaders["Content-Type"] || "text/plain";

    } else if (bodyType === "xml") {
      axiosData = bodyData || "";
      axiosHeaders["Content-Type"] = axiosHeaders["Content-Type"] || "application/xml";

    } else if (bodyType === "multipart") {
      // bodyData is { fieldName: { type:"text"|"file", value, bytes, filename, mimetype } }
      // Build a multipart body manually using FormData-style boundary
      const boundary = `----CURLmanBoundary${Date.now()}`;
      const parts    = [];

      for (const [name, part] of Object.entries(bodyData || {})) {
        if (part.type === "file") {
          const fileBytes = Buffer.from(part.bytes || []);
          const filename  = part.filename  || name;
          const mime      = part.mimetype  || "application/octet-stream";
          parts.push(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="${name}"; filename="${filename}"\r\n` +
            `Content-Type: ${mime}\r\n\r\n`
          );
          parts.push(fileBytes);
          parts.push(Buffer.from("\r\n"));
        } else {
          const val = part.value || "";
          parts.push(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
            `${val}\r\n`
          );
        }
      }
      parts.push(`--${boundary}--\r\n`);

      // Merge all parts into one Buffer
      axiosData = Buffer.concat(
        parts.map(p => typeof p === "string" ? Buffer.from(p, "utf8") : p)
      );
      axiosHeaders["Content-Type"] = `multipart/form-data; boundary=${boundary}`;

    } else if (bodyType === "raw") {
      // bodyData is { bytes: [...], mimetype: "..." }
      axiosData = Buffer.from((bodyData && bodyData.bytes) || []);
      axiosHeaders["Content-Type"] =
        axiosHeaders["Content-Type"] ||
        (bodyData && bodyData.mimetype) ||
        "application/octet-stream";
    }
  }

  // 4. Fire the request with axios
  let response;
  try {
    response = await axios({
      method:           m,
      url:              targetUrl,
      headers:          axiosHeaders,
      data:             axiosData,
      responseType:     "arraybuffer",   // always get raw bytes
      responseEncoding: "binary",
      maxRedirects:     10,
      timeout:          30000,
      validateStatus:   () => true,      // never throw on HTTP error status
      decompress:       true,            // axios handles gzip/br
    });
  } catch (e) {
    if (e.code === "ECONNREFUSED")  return sendError(res, 502, `Connection refused: ${targetUrl}`);
    if (e.code === "ENOTFOUND")     return sendError(res, 502, `Host not found: ${targetUrl}`);
    if (e.code === "ETIMEDOUT" || e.code === "ECONNABORTED")
                                    return sendError(res, 504, `Request timed out: ${targetUrl}`);
    return sendError(res, 502, `Proxy error: ${e.message}`);
  }

  const elapsed    = Date.now() - t0;
  const respBody   = Buffer.isBuffer(response.data)
    ? response.data
    : Buffer.from(response.data || "");

  // 5. Forward response headers (strip hop-by-hop + encoding headers)
  const outHeaders = { ...CORS_HEADERS };
  for (const [k, v] of Object.entries(response.headers || {})) {
    if (!STRIP_RESP.has(k.toLowerCase())) {
      outHeaders[k] = v;
    }
  }
  outHeaders["Content-Length"]    = String(respBody.length);
  outHeaders["X-Proxy-Time-Ms"]   = String(elapsed);
  outHeaders["Connection"]        = "close";

  // 6. Send response
  res.writeHead(response.status, outHeaders);
  if (m !== "HEAD") res.end(respBody);
  else              res.end();

  // 7. Log
  console.log(`  ${response.status}  ${m.padEnd(7)}  ${elapsed}ms  ${targetUrl}`);
}

// ── Main HTTP server ──────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsedPath = url.parse(req.url).pathname.replace(/\/+$/, "") || "/";
  const method     = req.method.toUpperCase();

  // CORS preflight
  if (method === "OPTIONS") {
    return sendPreflight(res);
  }

  // Health check
  if (parsedPath === "/ping") {
    return sendPing(res);
  }

  // Proxy endpoint
  if (parsedPath === "/" && method === "POST") {
    try {
      await handleProxy(req, res);
    } catch (e) {
      sendError(res, 500, `Unhandled error: ${e.message}`);
    }
    return;
  }

  // Unknown route
  sendError(res, 404, `Unknown endpoint: ${req.url}`);
});

server.on("error", err => {
  if (err.code === "EADDRINUSE") {
    console.error(`  Port ${PORT} is already in use. Use --port to pick another.`);
  } else {
    console.error(`  Server error: ${err.message}`);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log("");
  console.log("  CURLman Proxy Server (Node.js)");
  console.log(`  Listening on  http://${HOST}:${PORT}`);
  console.log("  Press Ctrl+C to stop");
  console.log("");
});

process.on("SIGINT",  () => { console.log("\n  Proxy stopped.\n"); process.exit(0); });
process.on("SIGTERM", () => { console.log("\n  Proxy stopped.\n"); process.exit(0); });
