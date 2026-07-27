const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json());

app.post('/api/leads', async (req, res) => {
  const {
    first_name,
    email,
    phone,
    business_motivation,
    goal_other_detail,
    sms_consent,
    tier_selected
  } = req.body || {};

  if (!first_name || !email || !phone) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  try {
    const fields = [
      `Name: ${first_name}`,
      `Email: ${email}`,
      `Phone: ${phone}`,
      `Motivation: ${business_motivation || 'N/A'}`,
      goal_other_detail ? `Other detail: ${goal_other_detail}` : null,
      `SMS Consent: ${sms_consent ? 'Yes' : 'No'}`,
      `Tier Selected: ${tier_selected || 'N/A'}`,
      `Submitted: ${new Date().toISOString()}`
    ].filter(Boolean).join('\n');

    await resend.emails.send({
      from: 'Ascend Authority <notifications@ascendauthority.com>',
      to: 'support@ascendauthority.com',
      subject: `New Ascend Authority Lead: ${first_name}`,
      text: fields
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Resend error:', error);
    return res.status(500).json({ ok: false, error: 'Failed to send notification' });
  }
});

app.get('/api/leads', (req, res) => {
  res.json({ ok: true, message: 'Leads endpoint is live' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
