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

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const N8N_RETURNS_WEBHOOK_URL = process.env.N8N_RETURNS_WEBHOOK_URL;

// ✅ NEW: Shopify Admin token for refund endpoints
const SHOPIFY_ADMIN_ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

// Your shop domain (fixed as requested)
const SHOPIFY_SHOP_DOMAIN = "311459-2.myshopify.com";

// Shopify REST API version (as you indicated)
const SHOPIFY_API_VERSION = "2026-01";

function verifyShopifyHmac(req) {
  const hmac = req.get("x-shopify-hmac-sha256");
  if (!hmac || !req.rawBody) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("base64");

  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

// -------------------------
// EXISTING WEBHOOK ENDPOINT
// -------------------------
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
    await fetch(N8N_RETURNS_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("Failed to forward to n8n", err);
  }
});

// =====================
// ✅ NEW: REFUND HELPERS
// =====================
function assertRefundEnv(res) {
  if (!SHOPIFY_ADMIN_ACCESS_TOKEN) {
    res
      .status(500)
      .json({ error: "Missing env var SHOPIFY_ADMIN_ACCESS_TOKEN" });
    return false;
  }
  return true;
}

async function shopifyAdminRequest({ method, path, body }) {
  const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}${path}`;

  const resp = await fetch(url, {
    method,
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await resp.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  return { ok: resp.ok, status: resp.status, json };
}

function parseOrderId(reqBody) {
  // Supports either order_id or orderId from n8n
  const orderId = reqBody?.order_id ?? reqBody?.orderId;
  if (!orderId || (typeof orderId !== "number" && typeof orderId !== "string")) {
    return null;
  }
  return String(orderId).trim();
}

// ----------------------------------------
// ✅ NEW (SAFE): Refund CALCULATE endpoint
// ----------------------------------------
// POST /shopify/refund/calculate
//
// Expects body like:
// {
//   "order_id": 12749945110905,
//   "refund": { ... }   // Shopify refund calculate payload
// }
//
// OR:
// {
//   "orderId": "12749945110905",
//   "refund": { ... }
// }
app.post("/shopify/refund/calculate", async (req, res) => {
  if (!assertRefundEnv(res)) return;

  const orderId = parseOrderId(req.body);
  if (!orderId) {
    return res.status(400).json({
      error:
        "Missing order_id (number/string) in request body. Provide order_id or orderId.",
    });
  }

  const refund = req.body?.refund;
  if (!refund || typeof refund !== "object" || Array.isArray(refund)) {
    return res.status(400).json({
      error:
        "Missing refund object in request body. Provide { order_id, refund: { ... } }",
    });
  }

  const { ok, status, json } = await shopifyAdminRequest({
    method: "POST",
    path: `/orders/${encodeURIComponent(orderId)}/refunds/calculate.json`,
    body: { refund },
  });

  return res.status(status).json(json);
});

// ----------------------------------------
// ✅ NEW (REAL): Refund CREATE endpoint
// ----------------------------------------
// POST /shopify/refund
//
// Expects body like:
// {
//   "order_id": 12749945110905,
//   "refund": { ... }   // Shopify refund create payload
// }
//
// OR:
// {
//   "orderId": "12749945110905",
//   "refund": { ... }
// }
app.post("/shopify/refund", async (req, res) => {
  if (!assertRefundEnv(res)) return;

  const orderId = parseOrderId(req.body);
  if (!orderId) {
    return res.status(400).json({
      error:
        "Missing order_id (number/string) in request body. Provide order_id or orderId.",
    });
  }

  const refund = req.body?.refund;
  if (!refund || typeof refund !== "object" || Array.isArray(refund)) {
    return res.status(400).json({
      error:
        "Missing refund object in request body. Provide { order_id, refund: { ... } }",
    });
  }

  const { ok, status, json } = await shopifyAdminRequest({
    method: "POST",
    path: `/orders/${encodeURIComponent(orderId)}/refunds.json`,
    body: { refund },
  });

  return res.status(status).json(json);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Shopify webhook proxy listening on ${PORT}`);
});
