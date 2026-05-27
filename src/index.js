import express from "express";
import dns from "dns";
import fetch from "node-fetch";
import whois from "whois-json";
import tls from "tls";

import { calculateRiskScore } from "./utils/score.js";

const app = express();
app.use(express.json());

// Root route
app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "SiteIntel API",
    message: 'Send POST /v1/report with { "target": "example.com" }',
  });
});

// Main intelligence endpoint
app.post("/v1/report", async (req, res) => {
  try {
    const target = req.body?.target;

    if (!target || typeof target !== "string") {
      return res.status(400).json({
        ok: false,
        error: "Missing or invalid 'target' field. Provide a domain or URL.",
      });
    }

    const domain = extractDomain(target);

    const [dnsInfo, whoisInfo, httpInfo, sslInfo] = await Promise.all([
      resolveDNS(domain),
      safeWhois(domain),
      fetchHttpInfo(target),
      safeSSL(domain),
    ]);

    const score = calculateRiskScore({ dnsInfo, whoisInfo, httpInfo, sslInfo });

    return res.json({
      ok: true,
      target,
      domain,
      score: score.value,
      category: score.category,
      details: {
        dns: dnsInfo,
        whois: whoisInfo,
        http: httpInfo,
        ssl: sslInfo,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      ok: false,
      error: "Internal Server Error",
      details: err?.message || "Unknown error",
    });
  }
});

// -------------------------------
// Helper Functions
// -------------------------------

// Extract domain from URL or raw input
function extractDomain(target) {
  try {
    if (!target.includes("://")) {
      return target.split("/")[0];
    }
    const url = new URL(target);
    return url.hostname;
  } catch {
    return target;
  }
}

// DNS lookup (A, MX, NS)
function resolveDNS(domain) {
  return new Promise((resolve) => {
    const result = {};

    dns.resolve4(domain, (err, addresses) => {
      result.a = err ? [] : addresses || [];

      dns.resolveMx(domain, (err2, mx) => {
        result.mx = err2 ? [] : mx || [];

        dns.resolveNs(domain, (err3, ns) => {
          result.ns = err3 ? [] : ns || [];
          resolve(result);
        });
      });
    });
  });
}

// WHOIS lookup (safe)
async function safeWhois(domain) {
  try {
    const data = await whois(domain);
    return {
      registrar: data.registrar || null,
      creationDate: data.creationDate || data.created || null,
      country: data.country || null,
    };
  } catch {
    return null;
  }
}

// HTTP info + security headers
async function fetchHttpInfo(target) {
  try {
    const url = target.includes("://") ? target : `https://${target}`;
    const res = await fetch(url, { method: "GET", redirect: "manual" });

    const securityHeaders = [
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
    ];

    const headers = {};
    for (const h of securityHeaders) {
      headers[h] = res.headers.get(h) || null;
    }

    return {
      status: res.status,
      redirected: res.status >= 300 && res.status < 400,
      headers,
    };
  } catch {
    return null;
  }
}

// Native TLS SSL certificate fetcher (no dependencies)
async function safeSSL(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();

        if (!cert || !cert.valid_to) {
          socket.end();
          return resolve(null);
        }

        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now = new Date();
        const daysRemaining = Math.round(
          (validTo - now) / (1000 * 60 * 60 * 24),
        );

        resolve({
          valid: now < validTo,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysRemaining,
          issuer: cert.issuer?.O || null,
        });

        socket.end();
      },
    );

    socket.on("error", () => resolve(null));
  });
}

// -------------------------------
// Start server
// -------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SiteIntel API listening on port ${PORT}`);
});
