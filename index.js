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

// Default Shopify Admin API version
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

  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
  } catch {
    return false;
  }
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

function getApiVersion(req) {
  // Allow override per request (useful when one endpoint breaks on 2026-01)
  return req.body?.apiVersion || req.query?.apiVersion || SHOPIFY_API_VERSION;
}

async function shopifyAdminRequest({
  shopDomain,
  accessToken,
  method,
  path,
  body,
  apiVersion,
}) {
  const version = apiVersion || SHOPIFY_API_VERSION;
  const url = `https://${shopDomain}/admin/api/${version}${path}`;

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
    err.url = url;
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
    version: "shopify-proxy-webhooks+refunds+fulfillments-001",
    hasWebhookSecret: Boolean(SHOPIFY_WEBHOOK_SECRET),
    hasN8nWebhookUrl: Boolean(N8N_RETURNS_WEBHOOK_URL),
    hasFallbackAdminToken: Boolean(SHOPIFY_ADMIN_ACCESS_TOKEN),
    defaultShopDomain: SHOPIFY_SHOP_DOMAIN || null,
    defaultApiVersion: SHOPIFY_API_VERSION,
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
// Refunds (kept intact)
// ---------------------
// POST /shopify/refund?dryRun=true|false
app.post("/shopify/refund", async (req, res) => {
  try {
    const dryRun =
      String(req.query.dryRun || "").toLowerCase() === "true" ||
      req.body?.dryRun === true;

    const shopDomain = getShopDomain(req);
    const apiVersion = getApiVersion(req);
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
          url: `https://${shopDomain}/admin/api/${apiVersion}${path}`,
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
      apiVersion,
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
      url: err?.url || null,
    });
  }
});

// POST /shopify/refund/calculate?dryRun=true|false
app.post("/shopify/refund/calculate", async (req, res) => {
  try {
    const dryRun =
      String(req.query.dryRun || "").toLowerCase() === "true" ||
      req.body?.dryRun === true;

    const shopDomain = getShopDomain(req);
    const apiVersion = getApiVersion(req);
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
          url: `https://${shopDomain}/admin/api/${apiVersion}${path}`,
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
      apiVersion,
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
      url: err?.url || null,
    });
  }
});

// ---------------------
// NEW: Create Fulfillment (NO DRY RUN)
// ---------------------
// This matches your exact desired Shopify endpoint + body style.
// POST /shopify/fulfillments/create
//
// Body:
// {
//   "shopDomain": "311459-2.myshopify.com",     // optional if env set
//   "apiVersion": "2025-10",                    // optional override (RECOMMENDED if 2026-01 returns 404)
//   "fulfillment": { ... }                      // REQUIRED, exact payload you want to send to Shopify
// }
//
// Token sources (in order):
// 1) Header: X-Shopify-Access-Token
// 2) Body: shopifyAccessToken
// 3) Env: SHOPIFY_ADMIN_ACCESS_TOKEN
//
app.post("/shopify/fulfillments/create", async (req, res) => {
  try {
    const shopDomain = getShopDomain(req);
    const apiVersion = getApiVersion(req);
    const accessToken = getShopifyAccessToken(req);

    const fulfillment = req.body?.fulfillment;

    if (!shopDomain) return res.status(400).json({ error: "Missing shopDomain" });
    if (!accessToken) {
      return res.status(500).json({
        error:
          "Missing Shopify access token. Provide header X-Shopify-Access-Token or body.shopifyAccessToken, or set SHOPIFY_ADMIN_ACCESS_TOKEN env var.",
      });
    }
    if (!fulfillment || typeof fulfillment !== "object") {
      return res
        .status(400)
        .json({ error: "Missing fulfillment object at body.fulfillment" });
    }

    const path = `/fulfillments.json`;
    const body = { fulfillment };

    const result = await shopifyAdminRequest({
      shopDomain,
      accessToken,
      method: "POST",
      path,
      body,
      apiVersion,
    });

    return res.json({ ok: true, result });
  } catch (err) {
    return res.status(err?.status || 500).json({
      error: err?.message || String(err),
      details: err?.details || null,
      url: err?.url || null,
      hint:
        err?.status === 404
          ? "Shopify returned 404. Try sending apiVersion='2025-10' in the request body for this endpoint."
          : null,
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
