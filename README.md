# NEMS

This version adds an opt-in sign-in mode for Render with Aiven PostgreSQL. It uses the existing NEMS account profiles, role checks, store assignments, encoding screens, reports, and Brevo invitation workflow.

## Test with the Aiven copy

1. Use a separate Render test service initially. Use a database copy reserved for testing. The app creates the private `nems_auth` schema at startup, so the database user must be allowed to create that schema and read `public.users`. The original NEMS policies that use Supabase-only functions were omitted from the Aiven test restore. Check store access before going live.
2. Set the following variables in the test service's Render **Environment** screen.

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | Aiven's Service URI for the database copy, including its private password |
   | `NEMS_DATABASE_CA_CERT` | Full contents of the Aiven CA certificate, including the BEGIN and END lines |
   | `NEMS_AUTH_MODE` | `local` |
   | `NEMS_PUBLIC_URL` | HTTPS address of the test NEMS site, which will receive password setup links |
   | `BREVO_API_KEY` | Existing NEMS Brevo key |
   | `BREVO_SENDER_EMAIL` | Existing verified Brevo sender |
   | `DB_POOL_MAX` | `5` as a starting point for Aiven Free |
   | `NEMS_DISABLE_BACKGROUND_JOBS` | `true` on the test service to avoid processing copied scheduled jobs and outgoing notification queues |

   Keep database passwords, URIs, and Brevo keys private. The local sign-in mode does not need Supabase settings.

3. Use **Forgot Password** with the registered email of the active admin test account and two active store test accounts. Each link expires in 30 minutes and can be used once. Set a password and sign in. Only request email for test accounts you control.
4. Confirm each store can read and save its own entries, cannot read or change the other store's entries, and sees saved expiration dates and quantities in its report. Check that an admin can create a new account, send its email invitation, and activate it. Verify rejection of an expired link and sign-in for inactive accounts. Check the Render logs for database errors from functions that may still refer to Supabase schemas.

## Production switch

Keep the original Supabase data and credentials as a rollback option. The Aiven copy is a snapshot. If records have changed since the backup, pause writes briefly to get a final copy and reconcile the data before redirecting the live service. Use the production HTTPS address for `NEMS_PUBLIC_URL`. Remove the test-only background-job flag after confirming pending notifications can be sent safely. Keep the production account configuration private.

Existing users keep their account and current store assignment. Their previous passwords were not included in the application database export. They use **Forgot Password** once to set a password through their registered mailbox, then log in with that password. Admins can continue sending invitations to new users. Existing sessions need a fresh login after the switch. Previous NEMS login activity is retained with the copied data, but Supabase-only sign-in history is unavailable in local mode.

If reverting the app, restore its previous database URL and Supabase Auth environment settings and reconcile any records written during the cutover before allowing writes again.
