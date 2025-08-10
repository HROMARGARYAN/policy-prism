# Stripe Monetization — Quick Setup

1) Create a Stripe account: https://dashboard.stripe.com/register
2) Create a recurring product:
   - Products → Add product → Name: "Policy Prism Pro"
   - Pricing: Recurring → Monthly (e.g., $9)
   - Copy the **Price ID** (looks like `price_...`)
3) Add env vars in Render:
   - STRIPE_SECRET_KEY = your Stripe secret (sk_live_... or sk_test_...)
   - STRIPE_PRICE_ID_MONTHLY = your Price ID
   - (Optional) STRIPE_SUCCESS_URL = https://YOURDOMAIN/dashboard
   - (Optional) STRIPE_CANCEL_URL = https://YOURDOMAIN/#pricing
   - STRIPE_WEBHOOK_SECRET = (after step 5)
4) Add the endpoints into server/index.js:
   - Add `import Stripe from 'stripe'` at the top with other imports.
   - Paste the code from `stripe/server_patch.js` into your file near the other routes.
5) Webhook (marks users Pro):
   - Stripe → Developers → Webhooks → Add endpoint
     - URL: https://YOURDOMAIN/billing/webhook
     - Events: checkout.session.completed, customer.subscription.updated, customer.subscription.deleted
   - Copy the **Webhook Signing Secret** (whsec_...) and set it as STRIPE_WEBHOOK_SECRET in Render.
6) Test in Stripe "test mode" using card 4242 4242 4242 4242 (any future date, any CVC/ZIP).
