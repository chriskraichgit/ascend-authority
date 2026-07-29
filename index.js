require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const cron = require("node-cron");
const { Resend } = require("resend");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Config ----------
const DATABASE_URL = process.env.DATABASE_URL;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET;
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@ascendauthority.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "Ascend Authority <support@ascendauthority.com>";
const ABANDONMENT_MINUTES = parseInt(process.env.ABANDONMENT_MINUTES || "30", 10);
const SIGNUP_URL = process.env.SIGNUP_URL || "https://ascendauthority.com/start";

if (!DATABASE_URL) console.error("[FATAL] DATABASE_URL is not set.");
if (!RESEND_API_KEY) console.error("[FATAL] RESEND_API_KEY is not set.");
if (!WHOP_WEBHOOK_SECRET) console.warn("[WARN] WHOP_WEBHOOK_SECRET is not set — webhook signature checks will fail closed.");

// This connects to a self-managed Postgres container on Railway's private
// network, which does not have SSL enabled. Only turn SSL on if the
// connection string explicitly asks for it (e.g. a managed provider that
// requires sslmode=require).
const useSSL = /sslmode=require/i.test(DATABASE_URL || "");
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false
});

const resend = new Resend(RESEND_API_KEY);

// Whop webhooks need the raw body for signature verification, so we capture it
// on this route specifically before the global json parser touches it.
app.use("/api/webhook/whop", express.raw({ type: "*/*" }));
app.use(express.json());

// ---------- Boot: run migrations ----------
async function runMigrations() {
  const migrationsDir = path.join(__dirname, "migrations");
  const files = fs.readdirSync(migrationsDir).sort();
  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), "utf8");
    await pool.query(sql);
    console.log(`[migrations] applied ${file}`);
  }
}

// ---------- Health check ----------
app.get("/health", (req, res) => res.status(200).json({ ok: true }));

// ---------- POST /api/lead ----------
app.post("/api/lead", async (req, res) => {
  try {
    const {
      first_name,
      email,
      phone,
      business_motivation,
      goal_other_detail,
      sms_consent,
      tier_selected
    } = req.body || {};

    if (!email || !first_name) {
      return res.status(400).json({ ok: false, error: "first_name and email are required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // Upsert by email. If the lead already converted, don't downgrade their
    // status back to pending on a re-submit — just refresh their details.
    await pool.query(
      `INSERT INTO leads (name, email, phone, business_motivation, goal_other_detail, sms_consent, tier_selected, status, notified, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', FALSE, NOW())
       ON CONFLICT (email) DO UPDATE SET
         name = EXCLUDED.name,
         phone = EXCLUDED.phone,
         business_motivation = EXCLUDED.business_motivation,
         goal_other_detail = EXCLUDED.goal_other_detail,
         sms_consent = EXCLUDED.sms_consent,
         tier_selected = EXCLUDED.tier_selected,
         status = CASE WHEN leads.status = 'converted' THEN leads.status ELSE 'pending' END,
         notified = CASE WHEN leads.status = 'converted' THEN leads.notified ELSE FALSE END,
         created_at = CASE WHEN leads.status = 'converted' THEN leads.created_at ELSE NOW() END`,
      [
        first_name,
        normalizedEmail,
        phone || null,
        business_motivation || null,
        goal_other_detail || null,
        Boolean(sms_consent),
        tier_selected || null
      ]
    );

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error("[/api/lead] error:", err);
    // Funnel UX should not break even if lead capture fails server-side.
    res.status(200).json({ ok: false });
  }
});

// ---------- POST /api/webhook/whop ----------
// Whop's dashboard issues secrets in "ws_<hex>" format. Their docs describe
// the Standard Webhooks spec (base64 secret), but in practice the dashboard
// secret doesn't fit that encoding — this is a known inconsistency on
// Whop's side (see whopio/whopsdk-python#6). We treat the secret as a raw
// string for the HMAC key (stripping the "ws_" prefix if present), which
// matches how most providers handle a plain issued secret.
function verifyWhopSignature(rawBody, headers) {
  const id = headers["webhook-id"];
  const timestamp = headers["webhook-timestamp"];
  const signatureHeader = headers["webhook-signature"];

  if (!WHOP_WEBHOOK_SECRET || !id || !timestamp || !signatureHeader) return false;

  const secretKey = WHOP_WEBHOOK_SECRET.startsWith("ws_")
    ? WHOP_WEBHOOK_SECRET.slice(3)
    : WHOP_WEBHOOK_SECRET;

  const signedContent = `${id}.${timestamp}.${rawBody.toString("utf8")}`;

  // Try both raw-utf8 and base64-decoded keys since Whop's exact scheme
  // isn't consistently documented — accept either to be resilient.
  const candidates = signatureHeader.split(" ").map((s) => s.split(",")[1]).filter(Boolean);

  const expectedRaw = crypto.createHmac("sha256", secretKey).update(signedContent).digest("base64");
  const expectedHex = crypto.createHmac("sha256", Buffer.from(secretKey, "hex")).update(signedContent).digest("base64");

  return candidates.some((sig) => {
    try {
      return (
        crypto.timingSafeEqual(Buffer.from(expectedRaw), Buffer.from(sig)) ||
        crypto.timingSafeEqual(Buffer.from(expectedHex), Buffer.from(sig))
      );
    } catch {
      return false;
    }
  });
}

app.post("/api/webhook/whop", async (req, res) => {
  try {
    const rawBody = req.body; // Buffer, thanks to express.raw() above

    if (!verifyWhopSignature(rawBody, req.headers)) {
      console.warn("[/api/webhook/whop] signature verification failed");
      return res.status(401).json({ ok: false, error: "invalid signature" });
    }

    const event = JSON.parse(rawBody.toString("utf8"));

    // Whop's dashboard (API v1) sends the event name as "membership_activated"
    // (some docs show it as "membership.activated" — accept either just in case).
    // The event root may use "event" or, on older payload shapes, "action".
    const eventName = event.event || event.action;
    if (eventName !== "membership_activated" && eventName !== "membership.activated") {
      // We only care about conversions here. Return 2xx so Whop doesn't retry.
      return res.status(200).json({ ok: true, ignored: true });
    }

    // Membership events carry a Membership object with User expanded.
    const email = event?.data?.user?.email || event?.data?.email;

    if (!email) {
      console.warn(`[/api/webhook/whop] ${eventName} with no email found, ignoring`);
      return res.status(200).json({ ok: true, ignored: true });
    }

    // Idempotent by nature (email lookup + fixed-value update), so Whop's
    // at-least-once delivery retries are safe without extra dedup logic.
    await pool.query(
      `UPDATE leads SET status = 'converted', converted_at = NOW() WHERE email = $1`,
      [String(email).trim().toLowerCase()]
    );

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error("[/api/webhook/whop] error:", err);
    res.status(500).json({ ok: false });
  }
});


// ---------- Abandonment check (runs every 5 min) ----------
async function nurtureEmailHtml(name) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; color: #1a1a1a;">
      <p>Hey ${name || "there"},</p>
      <p>You started signing up for Ascend Authority but didn't finish — curious what happened.</p>
      <p>If you're serious about taking that first step, this is where you start:</p>
      <p><a href="${SIGNUP_URL}" style="color: #7c3aed; font-weight: bold;">${SIGNUP_URL}</a></p>
      <p>No pressure — just didn't want you to miss it.</p>
      <p>— Chris</p>
    </div>
  `;
}

async function internalAlertHtml(lead) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; color: #1a1a1a;">
      <p>This lead started the Ascend Authority funnel but hasn't converted after ${ABANDONMENT_MINUTES} minutes:</p>
      <ul>
        <li><strong>Name:</strong> ${lead.name || "—"}</li>
        <li><strong>Email:</strong> ${lead.email}</li>
        <li><strong>Phone:</strong> ${lead.phone || "—"}</li>
        <li><strong>Tier selected:</strong> ${lead.tier_selected || "—"}</li>
        <li><strong>Motivation:</strong> ${lead.business_motivation || "—"}</li>
      </ul>
      <p>Reach out if you want to help them across the line.</p>
    </div>
  `;
}

async function runAbandonmentCheck() {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM leads
       WHERE status = 'pending'
         AND notified = FALSE
         AND created_at < NOW() - ($1 || ' minutes')::interval`,
      [ABANDONMENT_MINUTES]
    );

    if (rows.length === 0) return;

    console.log(`[abandonment] found ${rows.length} lead(s) to notify`);

    for (const lead of rows) {
      try {
        await resend.emails.send({
          from: FROM_EMAIL,
          to: lead.email,
          subject: "Didn't finish signing up?",
          html: await nurtureEmailHtml(lead.name)
        });

        await resend.emails.send({
          from: FROM_EMAIL,
          to: SUPPORT_EMAIL,
          subject: `Lead didn't convert: ${lead.name || lead.email}`,
          html: await internalAlertHtml(lead)
        });

        await pool.query(`UPDATE leads SET notified = TRUE WHERE id = $1`, [lead.id]);
        console.log(`[abandonment] notified for lead id=${lead.id} (${lead.email})`);
      } catch (sendErr) {
        console.error(`[abandonment] failed to notify lead id=${lead.id}:`, sendErr);
        // Leave notified = FALSE so it retries on the next cron tick.
      }
    }
  } catch (err) {
    console.error("[abandonment] query error:", err);
  }
}

// Every 5 minutes
cron.schedule("*/5 * * * *", runAbandonmentCheck);

// ---------- Boot ----------
runMigrations()
  .then(() => {
    app.listen(PORT, () => console.log(`Ascend Authority backend listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("[FATAL] migration failed, not starting server:", err);
    process.exit(1);
  });
