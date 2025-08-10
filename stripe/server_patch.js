// ---------- Stripe billing ----------
import Stripe from 'stripe';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.post('/billing/create-checkout-session', async (req, res) => {
  try {
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });
    const priceId = process.env.STRIPE_PRICE_ID_MONTHLY;
    if (!priceId) return res.status(400).json({ error: 'Missing STRIPE_PRICE_ID_MONTHLY' });
    const successUrl = process.env.STRIPE_SUCCESS_URL || `${req.protocol}://${req.get('host')}/dashboard`;
    const cancelUrl = process.env.STRIPE_CANCEL_URL || `${req.protocol}://${req.get('host')}/#pricing`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: successUrl + '?status=success',
      cancel_url: cancelUrl + '?status=cancelled',
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe session error', e.message);
    res.status(500).json({ error: 'Stripe session error' });
  }
});

function markPro(email) {
  try {
    const db = loadDb();
    db.users = db.users || [];
    const u = db.users.find(x => x.email.toLowerCase() === String(email || '').toLowerCase());
    if (u) u.pro = true;
    saveDb(db);
  } catch {}
}

app.post('/billing/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    if (!stripe) return res.status(400).end();
    const sig = req.headers['stripe-signature'];
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;
    if (secret) {
      event = stripe.webhooks.constructEvent(req.body, sig, secret);
    } else {
      event = JSON.parse(req.body);
    }
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const email = session.customer_details?.email;
      if (email) markPro(email);
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook error', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});
