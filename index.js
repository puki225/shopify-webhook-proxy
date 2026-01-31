import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();

// Capture RAW body (required for Shopify HMAC verification)
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const N8N_RETURNS_WEBHOOK_URL = process.env.N8N_RETURNS_WEBHOOK_URL;

function verifyShopifyHmac(req) {
  const hmac = req.get("x-shopify-hmac-sha256");
  if (!hmac || !req.rawBody) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("base64");

  return crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmac)
  );
}

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
      test: req.get("x-shopify-test") === "true"
    },
    body: req.body
  };

  // Respond immediately to Shopify
  res.status(200).json({ ok: true });

  // Forward to n8n asynchronously
  try {
    await fetch(N8N_RETURNS_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error("Failed to forward to n8n", err);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Shopify webhook proxy listening on ${PORT}`);
});
