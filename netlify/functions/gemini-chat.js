const https = require("https");

exports.handler = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  const apiKey = process.env.GEMINI_API_KEY;

  try {
    const bodyData = JSON.parse(event.body || "{}");
    const history = bodyData.history || [];
    const lastUserMessage = history.slice().reverse().find(m => m.role === "user")?.text || "Threat analysis request";

    if (!apiKey) {
      // Local SOC Co-pilot fallback response when GEMINI_API_KEY is not defined on Netlify
      const fallbackReply = `### ⚡ SOC Threat Hunting Co-pilot (Automated Assistant)

**Regarding your query:** *"${lastUserMessage.slice(0, 100)}"*

**Tactical Telemetry Guidance:**
1. **IP & Reputation Scans:** Ensure VirusTotal and AbuseIPDB API keys are updated in the **Settings** menu for live reputation scanning.
2. **Filter & Triage:** Use the top filter tabs (**Malicious**, **Suspicious**, **Clean**) and country dropdowns to isolate anomalous traffic.
3. **Export Reports:** Click **Export to Excel (.xlsx)** or **CSV** to save styled reports with detection percentages and vendor breakdowns.

*(Tip: If live Gemini API features are desired on Netlify, set GEMINI_API_KEY under Netlify Site Configuration > Environment variables, or continue using built-in reputation scanners zero-config!)*`;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ text: fallbackReply }),
      };
    }

    const contents = history.map((item) => ({
      role: item.role === "model" ? "model" : "user",
      parts: [{ text: item.text || item.message || "" }],
    }));

    const payload = JSON.stringify({
      contents,
      systemInstruction: {
        parts: [{
          text: `You are a highly capable Senior Incident Response & Security Operations Center (SOC) Specialist and Threat Hunting Co-pilot.
Provide expert guidance based on user queries, active spreadsheet records, or reputation scans.
Explain security alerts, cyber telemetry concepts, ports, protocol anomalies, and recommend containment strategies.
Format technical output using bold key indicators, space-conscious layout, and markdown bulleted lists.`
        }]
      }
    });

    const options = {
      hostname: "generativelanguage.googleapis.com",
      path: `/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    };

    const textResult = await new Promise((resolve) => {
      const req = https.request(options, (res) => {
        let respBody = "";
        res.on("data", (chunk) => (respBody += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(respBody);
            const responseText = parsed?.candidates?.[0]?.content?.parts?.[0]?.text || "No response generated";
            resolve({ text: responseText });
          } catch (e) {
            resolve({ error: "Failed to parse Gemini response" });
          }
        });
      });
      req.on("error", (e) => resolve({ error: e.message }));
      req.setTimeout(9000, () => {
        req.destroy();
        resolve({ error: "Gemini API request timed out" });
      });
      req.write(payload);
      req.end();
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(textResult),
    };
  } catch (err) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ error: err.message }),
    };
  }
};
