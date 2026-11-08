# Barrio MVP · Supabase

The project URL is `https://kfqyzenryurqtusoqnyx.supabase.co`.

## First database setup

1. In the Supabase dashboard, open **SQL Editor** for the Barrio MVP project.
2. Open and run `migrations/20261108000100_barrio_onboarding.sql` once.
3. In **Project Settings → API Keys**, copy the server-only **Secret key** (`sb_secret_...`) only into the API server environment as `SUPABASE_SECRET_KEY`. Never put it in `public/`, frontend JavaScript, Vercel client variables, or this repository.
4. Generate a separate random `JWT_SECRET` with at least 32 bytes and set it as a server secret.
5. Keep `PAYMENTS_MODE=simulated` while validating profile creation and database persistence.

The migration creates the data needed for account, profile, merchant, selected payment methods, and Pey CoDi account status. It stores only the CLABE's last four digits and Pey's account reference; the API sends the full CLABE to Pey and does not persist it.

## Current integration scope

The API can use Supabase for account registration/login, merchant profile creation, payment-method preferences, and Pey account registration/status. Merchant catalog, order checkout/history, and Pey webhook processing still use the existing SQL Server procedures and are not ready on the Supabase deployment. Those need PostgreSQL replacements before the full shopping/order flow is live.

This first pass keeps Barrio's existing application login (scrypt password hashes and short-lived Barrio tokens) in the Barrio tables; it does not use Supabase Auth yet. Email verification and password recovery must be added before opening self-registration broadly.

Pey registration is disabled unless the server is explicitly configured with `PAYMENTS_MODE=pey`, `PEY_LIVE_CHARGES_ENABLED=true`, `PEY_API_KEY`, and `PEY_WEBHOOK_SECRET`. Do not use production Pey settings just to test profile persistence.
