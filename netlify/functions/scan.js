const https = require("https");

// ── HARDCODED API KEY (No environment variable needed) ──
const VT_API_KEY = "96cbdd43beeb6dbe81302b11c27ff5d4d2acd9e5bd9126e258b4abe64e2ac38d";

function fetchVT(ip, apiKey) {
  return new Promise((resolve) => {
    const options = {
      hostname: "www.virustotal.com",
      path: `/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      method: "GET",
      headers: { "x-apikey": apiKey, Accept: "application/json" },
    };
    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const data = JSON.parse(body);
          if (res.statusCode === 429) {
            return resolve({ error: "RATE_LIMITED" });
          }
          if (res.statusCode !== 200) {
            return resolve({ error: data?.error?.message || `HTTP ${res.statusCode}` });
          }
          const attr = data.data.attributes;
          const stats = attr.last_analysis_stats || {};
          const results = attr.last_analysis_results || {};
          const total =
            (stats.harmless || 0) +
            (stats.malicious || 0) +
            (stats.suspicious || 0) +
            (stats.undetected || 0);
          const pct =
            total > 0
              ? Math.round(((stats.malicious || 0) / total) * 10000) / 100
              : 0;
          const votes = attr.total_votes || {};
          const community = (votes.harmless || 0) - (votes.malicious || 0);

          // Collect malicious vendor names for detail modal
          const maliciousVendors = Object.entries(results)
            .filter(([, v]) => v.category === "malicious")
            .map(([name]) => name)
            .slice(0, 10);

          const suspiciousVendors = Object.entries(results)
            .filter(([, v]) => v.category === "suspicious")
            .map(([name]) => name)
            .slice(0, 5);

          resolve({
            pct,
            community,
            country: attr.country || "—",
            asOwner: attr.as_owner || "—",
            harmless: stats.harmless || 0,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            undetected: stats.undetected || 0,
            total,
            maliciousVendors,
            suspiciousVendors,
            reputation: attr.reputation || 0,
            vtLink: `https://www.virustotal.com/gui/ip-address/${ip}`,
          });
        } catch (e) {
          resolve({ error: "Parse error: " + e.message });
        }
      });
    });
    req.on("error", (e) => resolve({ error: e.message }));
    req.setTimeout(15000, () => {
      req.destroy();
      resolve({ error: "Timeout" });
    });
    req.end();
  });
}

exports.handler = async (event) => {
  const ip = event.queryStringParameters?.ip || "";

  if (!ip) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Missing ip parameter" }),
    };
  }

  // Basic IP format validation before hitting VT
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip.trim())) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid IP format" }),
    };
  }

  const result = await fetchVT(ip.trim(), VT_API_KEY);
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
  };
};
