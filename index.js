import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();

// Capture RAW body (required for Shopify HMAC verification)
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// =====================
// ENVIRONMENT VARIABLES
// =====================
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const N8N_RETURNS_WEBHOOK_URL = process.env.N8N_RETURNS_WEBHOOK_URL;

// Optional fallback token (NOT required if you pass token per request)
const SHOPIFY_ADMIN_ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

// Optional default shop domain (if you don’t want to pass shopDomain each time)
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN; // e.g. 311459-2.myshopify.com

// Shopify Admin API version
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2026-01";

// =====================
// HELPERS
// =====================
function verifyShopifyHmac(req) {
  const hmac = req.get("x-shopify-hmac-sha256");
  if (!hmac || !req.rawBody) return false;
  if (!SHOPIFY_WEBHOOK_SECRET) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("base64");

  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

function getShopifyAccessToken(req) {
  const tokenFromHeader =
    req.get("x-shopify-access-token") || req.get("X-Shopify-Access-Token");
  const tokenFromBody = req.body?.shopifyAccessToken;
  return tokenFromHeader || tokenFromBody || SHOPIFY_ADMIN_ACCESS_TOKEN;
}

function getShopDomain(req) {
  return req.body?.shopDomain || SHOPIFY_SHOP_DOMAIN;
}

async function shopifyAdminRequest({ shopDomain, accessToken, method, path, body }) {
  const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}${path}`;

  const response = await fetch(url, {
    method,
    headers: {
      "X-Shopify-Access-Token": accessToken,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(`Shopify Admin API error ${response.status}`);
    err.status = response.status;
    err.details = json;
    throw err;
  }

  return json;
}

// =====================
// ROUTES
// =====================

// Healthcheck
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: "shopify-proxy-webhooks+refunds+fulfillments-002",
    hasWebhookSecret: Boolean(SHOPIFY_WEBHOOK_SECRET),
    hasN8nWebhookUrl: Boolean(N8N_RETURNS_WEBHOOK_URL),
    hasFallbackAdminToken: Boolean(SHOPIFY_ADMIN_ACCESS_TOKEN),
    defaultShopDomain: SHOPIFY_SHOP_DOMAIN || null,
    apiVersion: SHOPIFY_API_VERSION,
  });
});

// ---------------------
// Existing Webhooks endpoint (kept intact)
// ---------------------
app.post("/shopify/webhooks", async (req, res) => {
  if (!verifyShopifyHmac(req)) {
    return res.status(401).send("Invalid HMAC");
  }

  const payload = {
    shopify: {
      topic: req.get("x-shopify-topic"),
      webhook_id: req.get("x-shopify-webhook-id"),
      shop_domain: req.get("x-shopify-shop-domain"),
      triggered_at: req.get("x-shopify-triggered-at"),
      test: req.get("x-shopify-test") === "true",
    },
    body: req.body,
  };

  // Respond immediately to Shopify
  res.status(200).json({ ok: true });

  // Forward to n8n asynchronously
  try {
    if (!N8N_RETURNS_WEBHOOK_URL) {
      console.error("Missing env var N8N_RETURNS_WEBHOOK_URL");
      return;
    }

    await fetch(N8N_RETURNS_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("Failed to forward to n8n", err);
  }
});

// ---------------------
// Create Fulfillment (DIRECT EXECUTION, NO DRY RUN)
// ---------------------
// POST /shopify/fulfillments
//
// Body:
// {
//   "shopDomain": "311459-2.myshopify.com", // optional if env SHOPIFY_SHOP_DOMAIN set
//   "shopifyAccessToken": "...",            // optional if header token or env token is used
//   "fulfillment": {
//     "message": "Shipped via Amazon MCF",
//     "notify_customer": true,
//     "tracking_info": { "number": "...", "company": "..." },
//     "line_items_by_fulfillment_order": [{ "fulfillment_order_id": 123 }]
//   }
// }
app.post("/shopify/fulfillments", async (req, res) => {
  try {
    const shopDomain = getShopDomain(req);
    const accessToken = getShopifyAccessToken(req);

    if (!shopDomain) {
      return res.status(400).json({ error: "Missing shopDomain" });
    }
    if (!accessToken) {
      return res.status(500).json({
        error:
          "Missing Shopify access token. Provide header X-Shopify-Access-Token or body.shopifyAccessToken, or set SHOPIFY_ADMIN_ACCESS_TOKEN env var.",
      });
    }
    if (!req.body?.fulfillment || typeof req.body.fulfillment !== "object") {
      return res.status(400).json({
        error: "Invalid body: missing `fulfillment` object at body.fulfillment",
      });
    }

    const loi = req.body.fulfillment.line_items_by_fulfillment_order;
    if (!Array.isArray(loi) || loi.length === 0) {
      return res.status(400).json({
        error: "`line_items_by_fulfillment_order` must be a non-empty array.",
      });
    }

    // Ensure fulfillment_order_id is numeric (Shopify expects number)
    const fulfillmentOrderId = loi[0]?.fulfillment_order_id;
    if (typeof fulfillmentOrderId !== "number") {
      return res.status(400).json({
        error: "`fulfillment_order_id` must be a NUMBER (not string).",
        receivedType: typeof fulfillmentOrderId,
        receivedValue: fulfillmentOrderId,
      });
    }

    const result = await shopifyAdminRequest({
      shopDomain,
      accessToken,
      method: "POST",
      path: "/fulfillments.json",
      body: { fulfillment: req.body.fulfillment },
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
    });
  }
});

// ---------------------
// Create Refund (kept; supports dryRun)
// ---------------------
// POST /shopify/refund?dryRun=true|false
//
// Body format:
// {
//   "shopDomain": "311459-2.myshopify.com",     // optional if env SHOPIFY_SHOP_DOMAIN set
//   "orderId": 12749945110905,                  // REQUIRED
//   "refund": { ... },                          // REQUIRED (Shopify refund object)
//   "dryRun": true                              // optional alternative to query param
// }
app.post("/shopify/refund", async (req, res) => {
  try {
    const dryRun =
      String(req.query.dryRun || "").toLowerCase() === "true" ||
      req.body?.dryRun === true;

    const shopDomain = getShopDomain(req);
    const orderId = req.body?.orderId;
    const refundObj = req.body?.refund;
    const accessToken = getShopifyAccessToken(req);

    if (!shopDomain) return res.status(400).json({ error: "Missing shopDomain" });
    if (!orderId) return res.status(400).json({ error: "Missing orderId" });
    if (!refundObj || typeof refundObj !== "object") {
      return res.status(400).json({ error: "Missing refund object at body.refund" });
    }
    if (!accessToken) {
      return res.status(500).json({
        error:
          "Missing Shopify access token. Provide header X-Shopify-Access-Token or body.shopifyAccessToken, or set SHOPIFY_ADMIN_ACCESS_TOKEN env var.",
      });
    }

    const path = `/orders/${orderId}/refunds.json`;
    const body = { refund: refundObj };

    if (dryRun) {
      return res.json({
        ok: true,
        dryRun: true,
        wouldCall: {
          method: "POST",
          url: `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}${path}`,
          headers: {
            "X-Shopify-Access-Token": "*****",
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body,
        },
      });
    }

    const result = await shopifyAdminRequest({
      shopDomain,
      accessToken,
      method: "POST",
      path,
      body,
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
    });
  }
});

// ---------------------
// Calculate Refund (safe helper; supports dryRun)
// ---------------------
// POST /shopify/refund/calculate?dryRun=true|false
app.post("/shopify/refund/calculate", async (req, res) => {
  try {
    const dryRun =
      String(req.query.dryRun || "").toLowerCase() === "true" ||
      req.body?.dryRun === true;

    const shopDomain = getShopDomain(req);
    const orderId = req.body?.orderId;
    const refundObj = req.body?.refund;
    const accessToken = getShopifyAccessToken(req);

    if (!shopDomain) return res.status(400).json({ error: "Missing shopDomain" });
    if (!orderId) return res.status(400).json({ error: "Missing orderId" });
    if (!refundObj || typeof refundObj !== "object") {
      return res.status(400).json({ error: "Missing refund object at body.refund" });
    }
    if (!accessToken) {
      return res.status(500).json({
        error:
          "Missing Shopify access token. Provide header X-Shopify-Access-Token or body.shopifyAccessToken, or set SHOPIFY_ADMIN_ACCESS_TOKEN env var.",
      });
    }

    const path = `/orders/${orderId}/refunds/calculate.json`;
    const body = { refund: refundObj };

    if (dryRun) {
      return res.json({
        ok: true,
        dryRun: true,
        wouldCall: {
          method: "POST",
          url: `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}${path}`,
          headers: {
            "X-Shopify-Access-Token": "*****",
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body,
        },
      });
    }

    const result = await shopifyAdminRequest({
      shopDomain,
      accessToken,
      method: "POST",
      path,
      body,
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
    });
  }
});

// =====================
// START SERVER
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Shopify webhook proxy listening on ${PORT}`);
});
