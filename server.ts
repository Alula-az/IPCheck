import express from "express";
import path from "path";
import https from "https";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

const app = express();
const PORT = 3000;

// Enable JSON body parsing for Gemini data payloads
app.use(express.json({ limit: "15mb" }));

const DEFAULT_VT_API_KEY = "96cbdd43beeb6dbe81302b11c27ff5d4d2acd9e5bd9126e258b4abe64e2ac38d";

// Lazy initialization of the GoogleGenAI SDK to avoid application crash if API key is not present on startup.
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      throw new Error("GEMINI_API_KEY environment variable is not defined. Please set it under Settings > Secrets in the panel.");
    }
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build"
        }
      }
    });
  }
  return aiClient;
}

function fetchVT(ip: string, apiKey: string): Promise<any> {
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
            .filter(([, v]: any) => v.category === "malicious")
            .map(([name]) => name)
            .slice(0, 10);

          const suspiciousVendors = Object.entries(results)
            .filter(([, v]: any) => v.category === "suspicious")
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
        } catch (e: any) {
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

const DEFAULT_ABUSE_API_KEY = "40d64fe7f9f50624dcc558fb239a07d920e07ae88c1624460c268cb429ac34ffa04554974c39ed6a";

function fetchAbuseIPDB(ip: string, apiKey: string): Promise<any> {
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
        } catch (e: any) {
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

// ── ENDPOINT COMPATIBILITY WITH NETLIFY FUNCTIONS ──
app.get("/.netlify/functions/scan", async (req, res) => {
  const ip = (req.query.ip as string) || "";
  const queryKey = (req.query.key as string) || "";
  const apiKey = queryKey.trim() || DEFAULT_VT_API_KEY;

  if (!ip) {
    return res.status(400).json({ error: "Missing ip parameter" });
  }

  // Basic IP format validation before hitting VT
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip.trim())) {
    return res.status(400).json({ error: "Invalid IP format" });
  }

  const result = await fetchVT(ip.trim(), apiKey);
  res.json(result);
});

const abuseHandler = async (req: any, res: any) => {
  const ip = (req.query.ip as string) || "";
  const queryKey = (req.query.key as string) || "";
  const apiKey = queryKey.trim() || DEFAULT_ABUSE_API_KEY;

  if (!ip) {
    return res.status(400).json({ error: "Missing ip parameter" });
  }

  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip.trim())) {
    return res.status(400).json({ error: "Invalid IP format" });
  }

  const result = await fetchAbuseIPDB(ip.trim(), apiKey);
  res.json(result);
};

app.get("/api/abuseipdb/scan", abuseHandler);
app.get("/.netlify/functions/abuseipdb", abuseHandler);


// Multi-turn Gemini chatbot endpoint using gemini-3.5-flash
app.post("/api/gemini/chat", async (req, res) => {
  try {
    const { history } = req.body;
    if (!history || !Array.isArray(history)) {
      return res.status(400).json({ error: "Missing or invalid chat history payload" });
    }

    const ai = getGeminiClient();
    
    // Map history to Google GenAI Content form
    const contents = history.map((item: any) => ({
      role: item.role === "model" ? "model" : "user",
      parts: [{ text: item.text || item.message || "" }]
    }));

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: contents,
      config: {
        systemInstruction: `You are a highly capable Senior Incident Response & Security Operations Center (SOC) Specialist and Threat Hunting Co-pilot.
Provide expert guidance based on user queries, active spreadsheet records, or reputation scans.
Explain security alerts, cyber telemetry concepts, ports, protocol anomalies, and recommend containment strategies.
Format technical output using bold key indicators, space-conscious layout, and markdown bulleted lists.`
      }
    });

    res.json({ text: response.text });
  } catch (error: any) {
    console.error("Gemini Chat Error:", error);
    res.status(500).json({ error: error.message || "Threat co-pilot failed to respond." });
  }
});

// Bulk data summary and insight generator endpoint
app.post("/api/gemini/analyze", async (req, res) => {
  try {
    const { data, type } = req.body;
    if (!data) {
      return res.status(400).json({ error: "No telemetry data provided for analysis." });
    }

    const ai = getGeminiClient();

    let prompt = "";
    if (type === "weekly") {
      prompt = `Review this weekly cybersecurity reputation scanner spreadsheet database snippet:
${JSON.stringify(data, null, 2)}

Provide a senior director-level executive threat briefing summary:
1. Executive Triage Summary (Anomalies found, malicious IP detection rate).
2. Key Red Flags (Flagged hostnames, suspicious country concentrations, anomalous AS owners).
3. Recommended playbook steps for defense teams (containment, logging enhancements).
Structure the output elegantly with clean markdown subtitles and bullet targets. No fluff.`;
    } else {
      prompt = `Review this real-time reputation analysis report table for malicious/suspicious activity targets:
${JSON.stringify(data, null, 2)}

Produce a crisp incident analyst write-up:
1. Incident Severity Assessment & Highlights (critical, risky vectors).
2. Patterns & Geos (Top bad actors, anomalous indicators).
3. Containment Actions (Fist-tier containment response suggestions).
Format strictly using markdown with structured bold accents.`;
    }

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        systemInstruction: "You are a professional tactical incident management system that writes analytical security summaries. Be concise, expert, and professional."
      }
    });

    res.json({ text: response.text });
  } catch (error: any) {
    console.error("Gemini Triage Analysis Error:", error);
    res.status(500).json({ error: error.message || "Failed to generate security summary insights." });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
