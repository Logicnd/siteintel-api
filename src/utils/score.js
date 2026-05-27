export function calculateRiskScore({ dnsInfo, whoisInfo, httpInfo, sslInfo }) {
  let score = 0;
  const reasons = [];

  // WHOIS: very new domains are riskier
  if (whoisInfo?.creationDate) {
    const created = new Date(whoisInfo.creationDate);
    const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 30) {
      score += 30;
      reasons.push("Domain is less than 30 days old.");
    } else if (ageDays < 180) {
      score += 15;
      reasons.push("Domain is less than 6 months old.");
    }
  }

  // DNS: no MX records can be suspicious for some use cases
  if (dnsInfo && Array.isArray(dnsInfo.mx) && dnsInfo.mx.length === 0) {
    score += 10;
    reasons.push("No MX records found.");
  }

  // HTTP: missing security headers
  if (httpInfo?.headers) {
    const h = httpInfo.headers;
    if (!h["strict-transport-security"]) {
      score += 10;
      reasons.push("Missing Strict-Transport-Security header.");
    }
    if (!h["content-security-policy"]) {
      score += 10;
      reasons.push("Missing Content-Security-Policy header.");
    }
  }

  // SSL: invalid or expiring soon
  if (sslInfo) {
    if (!sslInfo.valid) {
      score += 25;
      reasons.push("SSL certificate is invalid.");
    } else if (sslInfo.daysRemaining !== null && sslInfo.daysRemaining < 14) {
      score += 10;
      reasons.push("SSL certificate expires in less than 14 days.");
    }
  }

  if (score > 100) score = 100;

  let category = "low";
  if (score >= 70) category = "high";
  else if (score >= 40) category = "medium";

  return {
    value: score,
    category,
    reasons,
  };
}
