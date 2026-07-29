CREATE TABLE IF NOT EXISTS leads (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  business_motivation TEXT,
  goal_other_detail TEXT,
  sms_consent BOOLEAN DEFAULT FALSE,
  tier_selected TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'converted'
  notified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  converted_at TIMESTAMPTZ,
  UNIQUE (email)
);

CREATE INDEX IF NOT EXISTS idx_leads_status_notified ON leads (status, notified, created_at);
