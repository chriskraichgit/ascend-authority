# Ascend Authority Backend

Replaces the GHL webhook workflow. Handles:
- Lead capture on funnel submit (`POST /api/lead`)
- Whop payment conversion tracking (`POST /api/webhook/whop`)
- 30-minute abandonment retargeting (nurture email to lead + internal alert to support@), runs every 5 min via an in-process cron job

## Setup

1. `npm install`
2. Make sure these env vars are set on Railway:
   - `DATABASE_URL` — auto-set once a Postgres plugin is attached to this service
   - `RESEND_API_KEY` — already set
   - `WHOP_WEBHOOK_SECRET` — from Whop dashboard → Developer → your webhook → copy the signing secret (base64 string)
   - `SUPPORT_EMAIL` — defaults to support@ascendauthority.com
   - `FROM_EMAIL` — defaults to "Ascend Authority <support@ascendauthority.com>", must be on a Resend-verified sending domain
   - `SIGNUP_URL` — defaults to https://ascendauthority.com/start
   - `ABANDONMENT_MINUTES` — defaults to 30
3. On boot, the app automatically runs the migration in `migrations/001_create_leads.sql` against `DATABASE_URL`.
4. Set the Whop webhook URL (in the Whop dashboard) to `https://<your-railway-domain>/api/webhook/whop`, subscribed to at least `payment.succeeded`.
5. `start.html` now posts to `https://ascend-authority-production.up.railway.app/api/lead` instead of the old GHL webhook. Update this URL if the Railway domain ever changes.

## Testing locally
- `GET /health` returns `{ ok: true }` once the server and DB migration are up.
- Submit the funnel and confirm a row appears in the `leads` table with `status = 'pending'`.
- Trigger a Whop test payment (or manually POST a signed test payload) and confirm the row flips to `status = 'converted'`.
- To test the abandonment path quickly, temporarily set `ABANDONMENT_MINUTES=1` on Railway, submit a lead, wait ~5 min for the cron tick, confirm both emails send and `notified` flips to true.
