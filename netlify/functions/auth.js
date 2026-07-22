exports.handler = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  const path = event.path || "";

  if (path.includes("/users")) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        admin: {
          username: "admin",
          password: "admin",
          name: "SOC Analyst",
          apiKey: "",
          abuseApiKey: "",
          threshold: 3,
          abuseThreshold: 30,
          skipAbuseIfVTEnabled: true,
          allowedVendors: ["apache", "Cisco ISE", "firewall"],
          excludedIPs: ["10"]
        }
      }),
    };
  }

  if (path.includes("/register")) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success: true }),
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ ok: true }),
  };
};
