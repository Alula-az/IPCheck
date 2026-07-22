const https = require("https");

const DEFAULT_ABUSE_API_KEY = "40d64fe7f9f50624dcc558fb239a07d920e07ae88c1624460c268cb429ac34ffa04554974c39ed6a";

function fetchAbuseIPDB(ip, apiKey) {
  return new Promise((resolve) => {
    const options = {
      hostname: "api.abuseipdb.com",
      path: `/api/v2/check?ipAddress=${encodeURIComponent(ip)}`,
      method: "GET",
      headers: {
        "Key": apiKey,
        "Accept": "application/json"
      },
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
            return resolve({ error: data?.errors?.[0]?.detail || `HTTP ${res.statusCode}` });
          }
          const checkData = data.data || {};
          resolve({
            ipAddress: checkData.ipAddress,
            abuseConfidenceScore: checkData.abuseConfidenceScore ?? 0,
            totalReports: checkData.totalReports ?? 0,
            isp: checkData.isp || "—",
            domain: checkData.domain || "—",
          });
        } catch (e) {
          resolve({ error: "Parse error: " + e.message });
        }
      });
    });
    req.on("error", (e) => resolve({ error: e.message || "Network error" }));
    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ error: "Timeout connecting to AbuseIPDB API" });
    });
    req.end();
  });
}

exports.handler = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  const ip = event.queryStringParameters?.ip || "";
  const queryKey = (event.queryStringParameters?.key || "").trim();
  const apiKey = queryKey || process.env.ABUSE_API_KEY || DEFAULT_ABUSE_API_KEY;

  if (!ip) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: "Missing ip parameter" }),
    };
  }

  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip.trim())) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: "Invalid IP format" }),
    };
  }

  try {
    const result = await fetchAbuseIPDB(ip.trim(), apiKey);
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result),
    };
  } catch (err) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ error: err.message || "Server error" }),
    };
  }
};
