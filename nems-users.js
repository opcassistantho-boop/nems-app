'use strict';
 
const crypto = require('crypto');
 
 
 
// NEMS ADMIN User Management. This module never exposes the Supabase secret to browsers.
 
module.exports = function registerUserRoutes({ app, pool, authenticate, adminOnly, passwordHistory }) {
 
    const secret = process.env.SUPABASE_SERVICE_ROLE_KEY;
 
    const base = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
 
    const roles = new Set(['ADMIN', 'HEAD', 'AOM', 'AS', 'STORE']);
 
    const fail = (res, code, message) => res.status(code).json({ error: message });
 
    const emailOf = v => String(v || '').trim().toLowerCase();
 
    const integer = v => Number.isSafeInteger(Number(v)) && Number(v) > 0 ? Number(v) : null;
 
    const route = [authenticate, adminOnly];
 
 
 
    // Brevo transactional email delivery. Keep credentials only in Render.
    const brevoApiKey = String(process.env.BREVO_API_KEY || '').trim();
    const brevoSenderEmail = String(process.env.BREVO_SENDER_EMAIL || '').trim();
    const brevoSenderName = String(process.env.BREVO_SENDER_NAME || 'CARD INDOGROSIR NEMS').trim();
 
    async function sendInvitationMessage(email, historyId) {
        if (!brevoApiKey) throw new Error('BREVO_NOT_CONFIGURED');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(brevoSenderEmail)) {
            throw new Error('BREVO_SENDER_NOT_CONFIGURED');
        }
        const redirectTo = (process.env.NEMS_PUBLIC_URL || 'https://nems-app.onrender.com').replace(/\/$/, '') + '/';
        const generated = await authAdmin('generate_link', 'POST', {
            type: 'recovery', email, options: { redirect_to: redirectTo }
        });
        const link = generated.action_link || generated.properties?.action_link;
        if (!link) throw new Error('SUPABASE_LINK_NOT_RETURNED');
        const safeLink = link.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            signal: AbortSignal.timeout(20000),
            headers: {
                'api-key': brevoApiKey,
                'Content-Type': 'application/json',
                accept: 'application/json'
            },
            body: JSON.stringify({
                sender: { name: brevoSenderName, email: brevoSenderEmail },
                to: [{ email }],
                tags: ['nems-reset-'+historyId],
                subject: 'NEMS - Set up your password',
                textContent: 'You have a NEMS account. Open this private link to set your password:\n\n' +
                    link + '\n\nIf you did not expect this invitation, ignore this message. ' +
                    'You can sign in only after an ADMIN activates your account.',
                htmlContent: '<p>You have a NEMS account.</p><p><a href="' + safeLink +
                    '">Set up your NEMS password</a></p><p>If you did not expect this invitation, ignore this message. ' +
                    'You can sign in only after an ADMIN activates your account.</p>'
            })
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = new Error('BREVO_SEND_FAILED: ' + (result.message || response.status));
            err.status = response.status;
            err.passwordMailRejected = true;
            throw err;
        }
        if (!result.messageId && !result.messageIds?.length) throw new Error('BREVO_NO_MESSAGE_ID');
        return {messageId:result.messageId||result.messageIds[0],httpStatus:response.status};
    }
 
 
    async function sendInvitation(email,source,actorEmail,ensureExisting=false){
        const id=await passwordHistory.begin({email,source,actorEmail,provider:'BREVO'});
        try{
            if(ensureExisting)await ensureInvitationAuthUser(email);
            const result=await sendInvitationMessage(email,id);
            await passwordHistory.finish(id,{state:'ACCEPTED',httpStatus:result.httpStatus,messageId:result.messageId,code:'DELIVERY_UNCONFIRMED'});
        }catch(error){
            const knownFailure=error.passwordMailRejected||/^(BREVO_NOT_CONFIGURED|BREVO_SENDER_NOT_CONFIGURED|SUPABASE_ADMIN_NOT_CONFIGURED|SUPABASE_LINK_NOT_RETURNED)$/.test(error.message)||Number.isInteger(error.status);
            const code=error.passwordMailRejected?'BREVO_REJECTED':knownFailure?(String(error.message).match(/^[A-Z_]+$/)?error.message:'AUTH_OR_PROVIDER_REJECTED'):'REQUEST_OUTCOME_UNCONFIRMED';
            try{await passwordHistory.finish(id,{state:knownFailure?'FAILED':'UNKNOWN',httpStatus:error.status||null,code});}
            catch(_){console.error('[NEMS password history] INVITATION_AUDIT_FAILED');}
            throw error;
        }
    }

    async function authAdmin(path, method, body) {
 
        if (!secret || !base) throw new Error('SUPABASE_ADMIN_NOT_CONFIGURED');
 
        const response = await fetch(`${base}/auth/v1/admin/${path}`, {
 
            method,
            signal: AbortSignal.timeout(20000),
 
            headers: { apikey: secret, Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
 
            ...(body === undefined ? {} : { body: JSON.stringify(body) })
 
        });
 
        const data = await response.json().catch(() => ({}));
 
        if (!response.ok) {
 
            const err = new Error(data.msg || data.message || data.error || 'Supabase Auth request failed');
 
            err.status = response.status;
 
            throw err;
 
        }
 
        return data;
 
    }
 
 
 
    async function validateStoreIds(client, ids) {
 
        if (!Array.isArray(ids) || ids.some(x => !integer(x))) return null;
 
        const unique = [...new Set(ids.map(Number))];
 
        if (!unique.length) return [];
 
        const result = await client.query(
 
            `SELECT store_id FROM public.stores WHERE store_id = ANY($1::bigint[]) AND status = 'ACTIVE'`,
 
            [unique]
 
        );
 
        return result.rowCount === unique.length ? unique : null;
 
    }
 
 
 
    // Serialize assignment edits before checking availability, including concurrent ADMIN requests.
    async function assertStoresAvailable(client, email, ids, role) {
        const table = role === 'AOM' ? 'aom_store_assignments' : 'as_store_assignments';
        const field = role === 'AOM' ? 'aom_email' : 'as_email';
        const conflict = await client.query(`
            SELECT s.store_name FROM public.${table} a
            JOIN public.stores s ON s.store_id=a.store_id
            WHERE a.store_id=ANY($1::bigint[]) AND LOWER(a.${field})<>$2
              AND NOT EXISTS (SELECT 1 FROM public.${table} own
                  WHERE own.store_id=a.store_id AND LOWER(own.${field})=$2)
            ORDER BY s.store_name LIMIT 1`, [ids, email]);
        if (conflict.rows.length) {
            const err = new Error(conflict.rows[0].store_name + ' is already assigned to another ' + role + '. Refresh the store list.');
            err.storeAssignmentConflict = true;
            throw err;
        }
    }

    async function setASStores(client, email, ids, role = 'AS') {
 
        const table = role === 'AOM' ? 'aom_store_assignments' : 'as_store_assignments';
        const field = role === 'AOM' ? 'aom_email' : 'as_email';
        await client.query(`DELETE FROM public.${table} WHERE LOWER(${field}) = $1`, [email]);
 
        for (const id of ids) {
 
            await client.query(
 
                `INSERT INTO public.${table} (${field}, store_id) VALUES ($1, $2)`,
 
                [email, id]
 
            );
 
        }
 
    }
 
 
 
    // Resolve the Supabase Auth identity without changing the NEMS account's status or role.
    async function findAuthUserByEmail(email) {
        // Admin listing is paginated; avoid treating an existing identity as absent.
        for (let page = 1; page <= 100; page++) {
            const result = await authAdmin(`users?page=${page}&per_page=1000`, 'GET');
            const users = Array.isArray(result.users) ? result.users : [];
            const found = users.find(u => emailOf(u.email) === email);
            if (found) return found;
            if (users.length < 1000) return null;
        }
        throw new Error('SUPABASE_AUTH_LOOKUP_LIMIT');
    }
 
    async function ensureInvitationAuthUser(email) {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const record = await client.query(
                'SELECT email, auth_user_id FROM public.users WHERE LOWER(email)=$1 FOR UPDATE',
                [email]
            );
            if (!record.rowCount) {
                await client.query('ROLLBACK');
                const err = new Error('NEMS_ACCOUNT_NOT_FOUND'); err.status = 404; throw err;
            }
            const linkedId = record.rows[0].auth_user_id;
            let authUser = null;
            if (linkedId) {
                try {
                    const found = await authAdmin(`users/${encodeURIComponent(linkedId)}`, 'GET');
                    authUser = found.user || found;
                } catch (error) {
                    if (error.status !== 404) throw error;
                }
                if (authUser && emailOf(authUser.email) !== email) {
                    throw new Error('AUTH_EMAIL_MISMATCH');
                }
            }
            if (!authUser) {
                authUser = await findAuthUserByEmail(email);
                if (!authUser) {
                    try {
                        const created = await authAdmin('users', 'POST', {
                            email,
                            password: crypto.randomBytes(48).toString('base64url'),
                            email_confirm: true,
                            app_metadata: { nems_pending_admin_approval: true }
                        });
                        authUser = created.user || created;
                    } catch (error) {
                        // Another request may have created the Auth identity concurrently.
                        if (error.status !== 422) throw error;
                        authUser = await findAuthUserByEmail(email);
                        if (!authUser) throw error;
                    }
                }
            }
            if (!authUser.id || emailOf(authUser.email) !== email) {
                throw new Error('AUTH_IDENTITY_VERIFICATION_FAILED');
            }
            if (String(linkedId || '') !== String(authUser.id)) {
                await client.query(
                    'UPDATE public.users SET auth_user_id=$1::uuid WHERE LOWER(email)=$2',
                    [authUser.id, email]
                );
            }
            await client.query('COMMIT');
            return authUser;
        } catch (error) {
            await client.query('ROLLBACK').catch(() => {});
            throw error;
        } finally {
            client.release();
        }
    }
 
    // ADMIN sends a password invitation to an existing NEMS account.
 
    app.post('/api/admin/users/password-link', ...route, async (req, res) => {
 
        const email = emailOf(req.body?.email);
 
        if (!email) return fail(res, 400, 'Email required');
 
        try {
 
            const existing = await pool.query('SELECT 1 FROM public.users WHERE LOWER(email)=$1', [email]);
 
            if (!existing.rowCount) return fail(res, 404, 'NEMS account not found');
 
            await sendInvitation(email,'ADMIN_PASSWORD_LINK',emailOf(req.user?.email),true);
 
            res.set('Cache-Control', 'no-store');
 
            return res.json({ message: 'Brevo accepted the password invitation for ' + email + '; delivery is unconfirmed.', sent: false, provider_accepted: true });
 
        } catch (err) {
 
            console.error('[NEMS USERS invitation]', err.message);
 
            return fail(res, 502, err.message === 'BREVO_NOT_CONFIGURED' ?
 
                'Brevo API key is not configured in Render' :
 
                err.message === 'BREVO_SENDER_NOT_CONFIGURED' ?
 
                'Brevo sender email is not configured in Render' :
 
                'Unable to send invitation email. Check Render logs and Brevo sender verification.');
 
        }
 
    });
 
 
 
    // ADMIN fallback: set one selected account's temporary password without email.
    // The password is sent only to Supabase Auth, never to audit tables or responses.
    app.post('/api/admin/users/temporary-password', ...route, async(req,res)=>{
        if(req.user?.role!=='ADMIN')return fail(res,403,'ADMIN access required');
        const email=emailOf(req.body?.email),password=req.body?.password;
        if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>255||
           typeof password!=='string'||password.length<12||password.length>128)
            return fail(res,400,'Select an account and enter a temporary password of 12–128 characters');
        let id=null,client=null,attempted=false,confirmed=false;
        try{
            const target=await pool.query('SELECT 1 FROM public.users WHERE LOWER(email)=$1',[email]);
            if(!target.rowCount)return fail(res,404,'NEMS account not found');
            id=crypto.randomUUID();
            // Durable audit before any external update, so interrupted requests remain visible.
            await pool.query(`INSERT INTO public.nems_admin_password_changes(change_id,recipient_email,changed_by)
                VALUES($1::uuid,$2,$3)`,[id,email,emailOf(req.user.email)]);
            const authUser=await ensureInvitationAuthUser(email);
            client=await pool.connect();await client.query('BEGIN');
            const linked=await client.query('SELECT email,auth_user_id,status FROM public.users WHERE LOWER(email)=$1 FOR UPDATE',[email]);
            if(!linked.rowCount||String(linked.rows[0].auth_user_id)!==String(authUser.id)||emailOf(authUser.email)!==email){
                const error=new Error('Identity changed');error.safeCode='AUTH_IDENTITY_CHANGED';throw error;
            }
            attempted=true;
            const updated=await authAdmin('users/'+encodeURIComponent(authUser.id),'PUT',{password});
            const identity=updated.user||updated;
            if(String(identity.id)!==String(authUser.id)||emailOf(identity.email)!==email){
                const error=new Error('Unconfirmed Auth response');error.safeCode='AUTH_RESPONSE_UNCONFIRMED';throw error;
            }
            confirmed=true;
            await client.query('COMMIT');client.release();client=null;
            await pool.query(`UPDATE public.nems_admin_password_changes SET change_status='CHANGED',
                result_code='PASSWORD_UPDATED',completed_at=clock_timestamp() WHERE change_id=$1::uuid`,[id]);
            res.set('Cache-Control','no-store');
            return res.json({email,changed:true,message:'Temporary password set. No reset email is required. Share it privately; the user can sign in and use Change Password. Account activation status is unchanged.'});
        }catch(error){
            if(client){await client.query('ROLLBACK').catch(()=>{});client.release();client=null;}
            const unknown=attempted&&!Number.isInteger(error.status);
            if(id)try{await pool.query(`UPDATE public.nems_admin_password_changes SET change_status=$2,
                result_code=$3,completed_at=clock_timestamp() WHERE change_id=$1::uuid`,
                [id,confirmed?'CHANGED':unknown?'UNKNOWN':'FAILED',confirmed?'PASSWORD_UPDATED':error.safeCode||(Number.isInteger(error.status)?'AUTH_REJECTED_'+error.status:unknown?'OUTCOME_UNCONFIRMED':'PASSWORD_NOT_UPDATED')]);}
                catch(_){console.error('[NEMS admin password] AUDIT_WRITE_FAILED');}
            console.error('[NEMS admin password]',error.code||'PASSWORD_UPDATE_ERROR');
            if(confirmed){res.set('Cache-Control','no-store');return res.json({email,changed:true,message:'Password changed, but the final audit update could not be confirmed. Share it privately and ask the user to use Change Password.'});}
            return fail(res,unknown?503:502,unknown?'Password update outcome is unconfirmed. Check whether the user can sign in with the temporary password before trying again.':'Unable to set password. Check Supabase account settings and that nems-admin-password.sql was installed.');
        }
    });
    app.get('/api/admin/password-change-history',...route,async(req,res)=>{
        if(req.user?.role!=='ADMIN')return fail(res,403,'ADMIN access required');
        try{
            const page=Math.max(1,Math.min(1000000,parseInt(req.query.page,10)||1)),term=String(req.query.search||'').trim().slice(0,100);
            const args=[term,51,(page-1)*50];
            const result=await pool.query(`SELECT change_id,recipient_email,changed_by,change_status,result_code,requested_at,completed_at
                FROM public.nems_admin_password_changes
                WHERE ($1::text='' OR POSITION(LOWER($1) IN LOWER(CONCAT_WS(' ',recipient_email,changed_by,change_status,result_code,requested_at::text)))>0)
                ORDER BY requested_at DESC,change_id DESC LIMIT $2 OFFSET $3`,args);
            res.set('Cache-Control','no-store');return res.json({records:result.rows.slice(0,50),page,has_more:result.rows.length>50});
        }catch(_){return fail(res,503,'Password Change History unavailable. Check nems-admin-password.sql.');}
    });

    // A recovery token changes only the authenticated Supabase user's password.
 
    // This does not approve/activate the corresponding NEMS account.
 
    app.post('/api/password/setup', async (req, res) => {
 
        const accessToken = req.body?.access_token;
 
        const password = req.body?.password;
 
        if (typeof accessToken !== 'string' || !accessToken ||
 
            typeof password !== 'string' || password.length < 12 || password.length > 128) {
 
            return fail(res, 400, 'Valid recovery token and password (12–128 characters) required');
 
        }
 
        try {
 
            const headers = { apikey: process.env.SUPABASE_ANON_KEY,
 
                Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };
 
            const identity = await fetch(`${base}/auth/v1/user`, { headers });
 
            if (!identity.ok) return fail(res, 401, 'Password setup link has expired or is invalid');
 
            const authUser = await identity.json();
 
            const account = await pool.query(
 
                'SELECT 1 FROM public.users WHERE auth_user_id=$1::uuid AND LOWER(email)=$2',
 
                [authUser.id, emailOf(authUser.email)]
 
            );
 
            if (!account.rowCount) return fail(res, 403, 'NEMS account not found');
 
            const changed = await fetch(`${base}/auth/v1/user`, {
 
                method: 'PUT', headers, body: JSON.stringify({ password })
 
            });
 
            if (!changed.ok) return fail(res, 400, 'Could not save password. Request a new link.');
 
            res.set('Cache-Control', 'no-store');
 
            return res.json({ message: 'Password saved. You may log in once ADMIN has activated your account.' });
 
        } catch (err) {
 
            console.error('[NEMS USERS password setup]', err.message);
 
            return fail(res, 500, 'Password setup temporarily unavailable');
 
        }
 
    });
 
 
 
    app.get('/api/admin/users/stores', ...route, async (req, res) => {
 
        try {
 
            const { rows } = await pool.query(
 
                `SELECT s.store_id, s.store_name, s.store_email, s.status,
                    ARRAY(SELECT LOWER(a.as_email) FROM public.as_store_assignments a WHERE a.store_id=s.store_id) AS assigned_as_emails,
                    ARRAY(SELECT LOWER(a.aom_email) FROM public.aom_store_assignments a WHERE a.store_id=s.store_id) AS assigned_aom_emails
                 FROM public.stores s ORDER BY s.store_name`
 
            );
 
            res.json(rows);
 
        } catch (err) {
 
            console.error('[NEMS USERS stores]', err);
 
            fail(res, 500, 'Unable to load stores');
 
        }
 
    });
 
 
 
    app.get('/api/admin/users', ...route, async (req, res) => {
 
        try {
 
            const { rows } = await pool.query(`
 
                SELECT u.email, u.full_name, u.role, u.status, u.store_name, u.created_at,
 
                    CASE WHEN u.role='AOM' THEN COALESCE((SELECT array_agg(DISTINCT aa.store_id ORDER BY aa.store_id) FROM public.aom_store_assignments aa WHERE LOWER(aa.aom_email)=LOWER(u.email)), ARRAY[]::bigint[]) ELSE COALESCE((SELECT array_agg(DISTINCT a.store_id ORDER BY a.store_id)
 
                              FROM public.as_store_assignments a
 
                              WHERE LOWER(a.as_email) = LOWER(u.email)), ARRAY[]::bigint[]) END AS assigned_store_ids
 
                FROM public.users u
 
                ORDER BY u.created_at DESC NULLS LAST, u.email
 
            `);
 
            res.json(rows);
 
        } catch (err) {
 
            console.error('[NEMS USERS list]', err);
 
            fail(res, 500, 'Unable to load users');
 
        }
 
    });
 
 
 
    app.post('/api/admin/users', ...route, async (req, res) => {
 
        const body = req.body || {};
 
        const email = emailOf(body.email);
 
        const name = String(body.full_name || '').trim();
 
        const role = String(body.role || '').toUpperCase();
 
        const password = body.password;
 
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255 ||
 
            !name || name.length > 255 || !roles.has(role) ||
 
            typeof password !== 'string' || password.length < 12 || password.length > 128) {
 
            return fail(res, 400, 'Provide a valid email, name, role and password (12–128 characters)');
 
        }
 
        // New ADMIN accounts also require explicit activation by an existing ADMIN.
 
        const client = await pool.connect().catch(() => null);
 
        if (!client) return fail(res, 500, 'Database unavailable');
 
        let authId = null;
 
        let committed = false;
 
        try {
 
            await client.query('BEGIN');
            await client.query('LOCK TABLE public.as_store_assignments, public.aom_store_assignments IN SHARE ROW EXCLUSIVE MODE');
 
            const duplicate = await client.query('SELECT 1 FROM public.users WHERE LOWER(email) = $1', [email]);
 
            if (duplicate.rowCount) {
 
                await client.query('ROLLBACK');
 
                return fail(res, 409, 'Email already exists in NEMS');
 
            }
 
            let storeName = null;
 
            let storeIds = [];
 
            if (role === 'STORE') {
 
                const id = integer(body.store_id);
 
                if (!id) { await client.query('ROLLBACK'); return fail(res, 400, 'Select a store'); }
 
                const store = await client.query(
 
                    `SELECT store_name, store_email FROM public.stores WHERE store_id=$1 AND status='ACTIVE'`, [id]
 
                );
 
                if (!store.rowCount || emailOf(store.rows[0].store_email) !== email) {
 
                    await client.query('ROLLBACK');
 
                    return fail(res, 400, 'STORE email must match the registered store email');
 
                }
 
                storeName = store.rows[0].store_name;
 
            } else if (['AS','AOM'].includes(role)) {
 
                storeIds = await validateStoreIds(client, body.store_ids);
 
                if (!storeIds || !storeIds.length) {
 
                    await client.query('ROLLBACK');
 
                    return fail(res, 400, 'Assign at least one active store to AS or AOM');
 
                }
                await assertStoresAvailable(client, email, storeIds, role);
 
            }
 
            const created = await authAdmin('users', 'POST', {
 
                email, password, email_confirm: true,
 
                app_metadata: { nems_pending_admin_approval: true }
 
            });
 
            authId = created.id || created.user?.id;
 
            if (!authId) throw new Error('Supabase did not return a user ID');
 
            await client.query(
 
                `INSERT INTO public.users (email, full_name, role, status, store_name, auth_user_id)
 
                 VALUES ($1, $2, $3, 'INACTIVE', $4, $5::uuid)`,
 
                [email, name, role, storeName, authId]
 
            );
 
            if (['AS','AOM'].includes(role)) await setASStores(client, email, storeIds, role);
 
            await client.query('COMMIT');
 
            committed = true;
 
            let invitationSent = false;
 
            try {
 
                await sendInvitation(email,'NEW_ACCOUNT_INVITATION',emailOf(req.user?.email));
 
                invitationSent = true;
 
            } catch (mailError) {
 
                console.error('[NEMS USERS new user invitation failed]', mailError.message);
 
            }
 
            return res.status(201).json({ email, role, status: 'INACTIVE',
 
                invitation_sent: false, invitation_provider_accepted: invitationSent,
 
                message: invitationSent ?
 
                    'User created. Brevo accepted the invitation request; delivery is unconfirmed. ADMIN activation required.' :
 
                    'User created, but invitation email failed. Use Send Invitation to retry. ADMIN activation required.' });
 
        } catch (err) {
 
            if (!committed) await client.query('ROLLBACK').catch(() => {});
 
            if (authId && !committed) {
 
                try { await authAdmin(`users/${encodeURIComponent(authId)}`, 'DELETE'); }
 
                catch (cleanupError) { console.error('[NEMS USERS orphaned Auth user requires manual reconciliation]', authId, cleanupError); }
 
            }
 
            if (err.storeAssignmentConflict) return fail(res, 409, err.message);
            console.error('[NEMS USERS create]', err);
 
            return fail(res, err.status === 422 ? 409 : 500,
 
                err.message === 'SUPABASE_ADMIN_NOT_CONFIGURED' ? 'Supabase administrator key is not configured' :
 
                err.status === 422 ? 'Account already exists in Supabase Authentication' : 'Unable to create user');
 
        } finally { client.release(); }
 
    });
 
 
 
    app.patch('/api/admin/users/:email', ...route, async (req, res) => {
 
        const email = emailOf(req.params.email);
 
        const body = req.body || {};
 
        const role = String(body.role || '').toUpperCase();
 
        const name = String(body.full_name || '').trim();
 
        const status = String(body.status || '').toUpperCase();
 
        if (!roles.has(role) || !['ACTIVE', 'INACTIVE'].includes(status) || !name || name.length > 255) {
 
            return fail(res, 400, 'Invalid name, role or status');
 
        }
 
        if (email === emailOf(req.user.email) && (status !== 'ACTIVE' || role !== 'ADMIN')) {
 
            return fail(res, 403, 'Cannot deactivate or demote your own ADMIN account');
 
        }
 
        const client = await pool.connect().catch(() => null);
 
        if (!client) return fail(res, 500, 'Database unavailable');
 
        try {
 
            await client.query('BEGIN');
            await client.query('LOCK TABLE public.as_store_assignments, public.aom_store_assignments IN SHARE ROW EXCLUSIVE MODE');
 
            const existing = await client.query(
 
                'SELECT email, role, status FROM public.users WHERE LOWER(email)=$1 FOR UPDATE', [email]
 
            );
 
            if (!existing.rowCount) { await client.query('ROLLBACK'); return fail(res, 404, 'User not found'); }
 
            if (existing.rows[0].role === 'ADMIN' && (role !== 'ADMIN' || status !== 'ACTIVE')) {
 
                const count = await client.query("SELECT COUNT(*)::integer AS n FROM public.users WHERE role='ADMIN' AND status='ACTIVE'");
 
                if (count.rows[0].n <= 1) {
 
                    await client.query('ROLLBACK');
 
                    return fail(res, 403, 'Cannot remove the last active ADMIN');
 
                }
 
            }
 
            let storeName = null;
 
            let storeIds = [];
 
            if (role === 'STORE') {
 
                const id = integer(body.store_id);
 
                const store = id ? await client.query(
 
                    `SELECT store_name, store_email FROM public.stores WHERE store_id=$1 AND status='ACTIVE'`, [id]
 
                ) : { rows: [] };
 
                if (!store.rows.length || emailOf(store.rows[0].store_email) !== email) {
 
                    await client.query('ROLLBACK');
 
                    return fail(res, 400, 'STORE email must match the registered store email');
 
                }
 
                storeName = store.rows[0].store_name;
 
            } else if (['AS','AOM'].includes(role)) {
 
                storeIds = await validateStoreIds(client, body.store_ids);
 
                if (!storeIds || !storeIds.length) {
 
                    await client.query('ROLLBACK');
 
                    return fail(res, 400, 'Assign at least one active store to AS or AOM');
 
                }
                await assertStoresAvailable(client, email, storeIds, role);
 
            }
 
            await client.query(
 
                'UPDATE public.users SET full_name=$1, role=$2, status=$3, store_name=$4 WHERE LOWER(email)=$5',
 
                [name, role, status, storeName, email]
 
            );
 
            await setASStores(client, email, role === 'AS' ? storeIds : [], 'AS');
            await setASStores(client, email, role === 'AOM' ? storeIds : [], 'AOM');
 
            await client.query('COMMIT');
 
            return res.json({ email, full_name: name, role, status, store_name: storeName });
 
        } catch (err) {
 
            await client.query('ROLLBACK').catch(() => {});
 
            if (err.storeAssignmentConflict) return fail(res, 409, err.message);
            console.error('[NEMS USERS update]', err);
 
            return fail(res, 500, 'Unable to update user');
 
        } finally { client.release(); }
 
    });
 
};
