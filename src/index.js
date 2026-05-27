import express from "express";
import dns from "dns";
import fetch from "node-fetch";
import whois from "whois-json";
import sslInfo from "ssl-info";

import { calculateRiskScore } from "./utils/score.js";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "SiteIntel API",
    message: 'Send POST /v1/report with { "target": "example.com" }',
  });
});

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

// --- helpers ---

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

async function safeSSL(domain) {
  try {
    const info = await sslInfo(domain);

    return {
      valid: info.valid,
      daysRemaining: info.daysRemaining,
      validFrom: info.validFrom,
      validTo: info.validTo,
      issuer: info.issuer,
    };
  } catch {
    return null;
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SiteIntel API listening on port ${PORT}`);
});
