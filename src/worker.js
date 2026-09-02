import { parseBBVACSV, parseBBVAEstadoCuenta } from './lib/parser.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

// ── Google Auth ────────────────────────────────────────────────────
async function verifyGoogleToken(token) {
  const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
  if (!res.ok) return null;
  const data = await res.json();
  if (!data.email) return null;
  return { email: data.email, name: data.name || data.email };
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(db, email) {
  const token  = generateToken();
  const expiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await db.prepare('INSERT INTO sessions (token, email, expiry) VALUES (?, ?, ?)').bind(token, email, expiry).run();
  return token;
}

async function getSessionEmail(db, token) {
  if (!token) return null;
  const row = await db.prepare('SELECT email, expiry FROM sessions WHERE token = ?').bind(token).first();
  if (!row) return null;
  if (Date.now() > row.expiry) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return row.email;
}

// Obtener household_id del usuario (o crear uno si no tiene)
async function getOrCreateHousehold(db, email) {
  const user = await db.prepare('SELECT household_id FROM users WHERE email = ?').bind(email).first();
  if (user?.household_id) return user.household_id;

  // Crear nuevo hogar
  const hid = generateToken().slice(0, 16);
  await db.prepare('INSERT INTO households (id) VALUES (?)').bind(hid).run();
  await db.prepare('UPDATE users SET household_id = ? WHERE email = ?').bind(hid, email).run();
  return hid;
}

// ── Router ─────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    try {
      if (path === '/api/auth/google'     && method === 'POST') return handleGoogleLogin(request, env);
      if (path === '/api/auth/join'       && method === 'POST') return handleJoinHousehold(request, env);

      const authHeader   = request.headers.get('Authorization') || '';
      const sessionToken = authHeader.replace('Bearer ', '').trim();
      const email        = await getSessionEmail(env.DB, sessionToken);
      if (!email) return json({ error: 'No autorizado' }, 401);

      const hid = await getOrCreateHousehold(env.DB, email);

      if (path === '/api/me'              && method === 'GET')  return handleMe(env, email, hid);
      if (path === '/api/invite'          && method === 'POST') return handleCreateInvite(env, email, hid);
      if (path === '/api/accounts'        && method === 'GET')  return handleListAccounts(env, hid);
      if (path === '/api/accounts'        && method === 'POST') return handleCreateAccount(request, env, email, hid);
      if (path.startsWith('/api/accounts/') && method === 'PUT') return handleUpdateAccount(request, env, hid, path.split('/')[3]);
      if (path === '/api/categories'      && method === 'GET')  return handleListCategories(env);
      if (path.startsWith('/api/transactions/') && method === 'DELETE') return handleDeleteTransaction(env, hid, path.split('/')[3]);
      if (path === '/api/transactions'    && method === 'GET')  return handleListTransactions(url, env, hid);
      if (path === '/api/transactions'    && method === 'POST') return handleCreateTransaction(request, env, email, hid);
      if (path === '/api/import/bbva'     && method === 'POST') return handleImportBBVA(request, env, email, hid);
      if (path === '/api/import/bbva-pdf' && method === 'POST') return handleImportBBVAPDF(request, env, email, hid);

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: err.message }, 500);
    }
  },
};

// ── POST /api/auth/google ──────────────────────────────────────────
async function handleGoogleLogin(request, env) {
  const { idToken } = await request.json();
  if (!idToken) return json({ error: 'idToken requerido' }, 400);

  const googleUser = await verifyGoogleToken(idToken);
  if (!googleUser) return json({ error: 'Token de Google inválido' }, 401);

  // Lista blanca de correos autorizados (separados por coma en el secret ALLOWED_EMAILS)
  if (env.ALLOWED_EMAILS) {
    const allowed = env.ALLOWED_EMAILS.split(',').map(e => e.trim().toLowerCase());
    if (!allowed.includes(googleUser.email.toLowerCase())) {
      return json({ error: 'Correo no autorizado' }, 403);
    }
  }

  const existing = await env.DB.prepare('SELECT email, household_id FROM users WHERE email = ?').bind(googleUser.email).first();
  if (!existing) {
    await env.DB.prepare('INSERT INTO users (email, name) VALUES (?, ?)').bind(googleUser.email, googleUser.name).run();
  }

  const sessionToken = await createSession(env.DB, googleUser.email);
  const hid          = await getOrCreateHousehold(env.DB, googleUser.email);
  const cuentas      = await env.DB.prepare('SELECT id FROM accounts WHERE household_id = ? LIMIT 1').bind(hid).first();

  return json({
    ok: true,
    sessionToken,
    user: { email: googleUser.email, name: googleUser.name },
    needsOnboarding: !cuentas,
  });
}

// ── POST /api/invite — genera código de invitación al hogar ───────
async function handleCreateInvite(env, email, hid) {
  const code = generateToken().slice(0, 8).toUpperCase();
  await env.DB.prepare('INSERT INTO household_invites (id, household_id, invited_by, invite_code) VALUES (?, ?, ?, ?)')
    .bind(generateToken().slice(0,16), hid, email, code).run();
  return json({ ok: true, code });
}

// ── POST /api/auth/join — unirse a un hogar con código ─────────────
async function handleJoinHousehold(request, env) {
  const { idToken, code } = await request.json();
  if (!idToken || !code) return json({ error: 'idToken y code son requeridos' }, 400);

  const googleUser = await verifyGoogleToken(idToken);
  if (!googleUser) return json({ error: 'Token de Google inválido' }, 401);

  if (env.ALLOWED_EMAILS) {
    const allowed = env.ALLOWED_EMAILS.split(',').map(e => e.trim().toLowerCase());
    if (!allowed.includes(googleUser.email.toLowerCase())) {
      return json({ error: 'Correo no autorizado' }, 403);
    }
  }

  const invite = await env.DB.prepare('SELECT household_id FROM household_invites WHERE invite_code = ? AND used = 0').bind(code.toUpperCase()).first();
  if (!invite) return json({ error: 'Código inválido o ya usado' }, 400);

  // Crear o actualizar usuario con el household del invitado
  const existing = await env.DB.prepare('SELECT email FROM users WHERE email = ?').bind(googleUser.email).first();
  if (!existing) {
    await env.DB.prepare('INSERT INTO users (email, name, household_id) VALUES (?, ?, ?)').bind(googleUser.email, googleUser.name, invite.household_id).run();
  } else {
    await env.DB.prepare('UPDATE users SET household_id = ? WHERE email = ?').bind(invite.household_id, googleUser.email).run();
  }

  // Marcar invitación como usada
  await env.DB.prepare('UPDATE household_invites SET used = 1 WHERE invite_code = ?').bind(code.toUpperCase()).run();

  const sessionToken = await createSession(env.DB, googleUser.email);
  return json({ ok: true, sessionToken, user: { email: googleUser.email, name: googleUser.name }, needsOnboarding: false });
}

// ── GET /api/me ────────────────────────────────────────────────────
async function handleMe(env, email, hid) {
  const user    = await env.DB.prepare('SELECT email, name, created_at FROM users WHERE email = ?').bind(email).first();
  const members = await env.DB.prepare('SELECT email, name FROM users WHERE household_id = ?').bind(hid).all();
  return json({ ok: true, user, household: { id: hid, members: members.results } });
}

// ── GET /api/accounts ──────────────────────────────────────────────
async function handleListAccounts(env, hid) {
  const { results } = await env.DB
    .prepare('SELECT id, name, type, currency, current_balance, credit_limit, cut_date, payment_date FROM accounts WHERE household_id = ? AND is_active = 1 ORDER BY name')
    .bind(hid).all();
  return json({ ok: true, accounts: results });
}

// ── POST /api/accounts ─────────────────────────────────────────────
async function handleCreateAccount(request, env, email, hid) {
  const { name, type, currency = 'MXN', initial_balance = 0, credit_limit = null, cut_date = null, payment_date = null } = await request.json();
  if (!name || !type) return json({ error: 'name y type son requeridos' }, 400);

  const id = crypto.randomUUID();
  await env.DB
    .prepare('INSERT INTO accounts (id, name, type, currency, initial_balance, current_balance, credit_limit, cut_date, payment_date, user_email, household_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, name, type, currency, initial_balance, initial_balance, credit_limit, cut_date, payment_date, email, hid)
    .run();

  return json({ ok: true, account: { id, name, type, currency, current_balance: initial_balance, credit_limit, cut_date, payment_date } }, 201);
}

// ── PUT /api/accounts/:id ──────────────────────────────────────────
async function handleUpdateAccount(request, env, hid, id) {
  if (!id) return json({ error: 'ID requerido' }, 400);
  const account = await env.DB.prepare('SELECT id FROM accounts WHERE id = ? AND household_id = ? AND is_active = 1').bind(id, hid).first();
  if (!account) return json({ error: 'Cuenta no encontrada' }, 404);

  const body = await request.json();
  const updates = [], params = [];
  const { name, type, current_balance, credit_limit, cut_date, payment_date } = body;
  if (name !== undefined)            { updates.push('name = ?');            params.push(name); }
  if (type !== undefined)            { updates.push('type = ?');            params.push(type); }
  if (current_balance !== undefined) { updates.push('current_balance = ?'); params.push(parseFloat(current_balance)); }
  if (credit_limit !== undefined)    { updates.push('credit_limit = ?');    params.push(credit_limit ? parseFloat(credit_limit) : null); }
  if (cut_date !== undefined)        { updates.push('cut_date = ?');        params.push(cut_date ? parseInt(cut_date) : null); }
  if (payment_date !== undefined)    { updates.push('payment_date = ?');    params.push(payment_date ? parseInt(payment_date) : null); }
  if (!updates.length) return json({ error: 'Nada que actualizar' }, 400);

  params.push(id, hid);
  await env.DB.prepare(`UPDATE accounts SET ${updates.join(', ')} WHERE id = ? AND household_id = ?`).bind(...params).run();

  const updated = await env.DB.prepare('SELECT id, name, type, currency, current_balance, credit_limit, cut_date, payment_date FROM accounts WHERE id = ?').bind(id).first();
  return json({ ok: true, account: updated });
}

// ── GET /api/categories ────────────────────────────────────────────
async function handleListCategories(env) {
  const { results } = await env.DB
    .prepare('SELECT id, name, type, icon, color FROM categories WHERE is_active = 1 ORDER BY type, name')
    .all();
  return json({ ok: true, categories: results });
}

// ── POST /api/transactions ─────────────────────────────────────────
async function handleCreateTransaction(request, env, email, hid) {
  let account_id, category_id, amount, lat, lng, nota, file;

  const ct = request.headers.get('content-type') || '';
  if (ct.includes('multipart/form-data')) {
    const fd = await request.formData();
    account_id  = fd.get('account_id');
    category_id = fd.get('category_id');
    amount      = parseFloat(fd.get('amount'));
    lat         = fd.get('lat')  ? parseFloat(fd.get('lat'))  : null;
    lng         = fd.get('lng')  ? parseFloat(fd.get('lng'))  : null;
    nota        = fd.get('nota') || null;
    file        = fd.get('file');
    if (file && !(file instanceof File)) file = null;
  } else {
    const body = await request.json();
    ({ account_id, category_id, amount, lat, lng, nota } = body);
  }

  if (!account_id || amount === undefined || isNaN(amount)) {
    return json({ error: 'account_id y amount son requeridos' }, 400);
  }

  const account = await env.DB
    .prepare('SELECT id FROM accounts WHERE id = ? AND household_id = ? AND is_active = 1')
    .bind(account_id, hid).first();
  if (!account) return json({ error: 'Cuenta no encontrada' }, 400);

  let source = 'MANUAL';
  if (file) source = (file.type || '').startsWith('audio/') ? 'VOICE' : 'PHOTO';

  const id = crypto.randomUUID();
  await env.DB
    .prepare(`INSERT INTO transactions (id, account_id, category_id, amount, description, lat, lng, source, status, user_email, transaction_date)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, CURRENT_TIMESTAMP)`)
    .bind(id, account_id, category_id ?? null, amount, nota, lat, lng, source, email)
    .run();

  if (file && env.R2) {
    const filename = file.name || `attachment_${Date.now()}`;
    const r2Key    = `${hid}/${id}/${filename}`;
    await env.R2.put(r2Key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
    const fileType = (file.type || '').startsWith('audio/') ? 'AUDIO' : 'IMAGE';
    await env.DB
      .prepare('INSERT INTO attachments (id, transaction_id, storage_provider, external_id, file_type, file_name, mime_type) VALUES (?, ?, \'R2\', ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), id, r2Key, fileType, filename, file.type).run();
  }

  const tx = await env.DB
    .prepare(`SELECT t.*, a.name AS account_name, a.currency,
                     c.name AS category_name, c.icon AS category_icon
              FROM transactions t
              JOIN accounts a ON t.account_id = a.id
              LEFT JOIN categories c ON t.category_id = c.id
              WHERE t.id = ?`)
    .bind(id).first();

  return json({ ok: true, transaction: tx }, 201);
}

// ── DELETE /api/transactions/:id ──────────────────────────────────
async function handleDeleteTransaction(env, hid, id) {
  if (!id) return json({ error: 'ID requerido' }, 400);
  const tx = await env.DB.prepare(
    'SELECT t.id, t.account_id, t.amount FROM transactions t JOIN accounts a ON t.account_id = a.id WHERE t.id = ? AND a.household_id = ?'
  ).bind(id, hid).first();
  if (!tx) return json({ error: 'Transacción no encontrada' }, 404);

  await env.DB.prepare('DELETE FROM transactions WHERE id = ?').bind(id).run();
  await env.DB.prepare('UPDATE accounts SET current_balance = current_balance - ? WHERE id = ?').bind(tx.amount, tx.account_id).run();
  return json({ ok: true });
}

// ── GET /api/transactions ──────────────────────────────────────────
async function handleListTransactions(url, env, hid) {
  const account_id = url.searchParams.get('account_id');
  const status     = url.searchParams.get('status');
  const from       = url.searchParams.get('from');
  const to         = url.searchParams.get('to');
  const limit      = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);

  let query = `SELECT t.id, t.account_id, t.category_id, t.amount, t.description,
                      t.transaction_date, t.status, t.source, t.lat, t.lng,
                      t.user_email, a.name AS account_name, a.currency,
                      c.name AS category_name, c.icon AS category_icon
               FROM transactions t
               JOIN accounts a ON t.account_id = a.id
               LEFT JOIN categories c ON t.category_id = c.id
               WHERE a.household_id = ?`;
  const params = [hid];

  if (account_id) { query += ' AND t.account_id = ?';        params.push(account_id); }
  if (status)     { query += ' AND t.status = ?';            params.push(status); }
  if (from)       { query += ' AND t.transaction_date >= ?'; params.push(from + ' 00:00:00'); }
  if (to)         { query += ' AND t.transaction_date <= ?'; params.push(to + ' 23:59:59'); }
  query += ' ORDER BY t.transaction_date DESC LIMIT ?';
  params.push(limit);

  const { results } = await env.DB.prepare(query).bind(...params).all();
  return json({ ok: true, transactions: results });
}

// ── POST /api/import/bbva ──────────────────────────────────────────
async function handleImportBBVA(request, env, email, hid) {
  const { csvText, account_id } = await request.json();
  if (!csvText || !account_id) return json({ error: 'csvText y account_id son requeridos' }, 400);

  const account = await env.DB.prepare('SELECT id FROM accounts WHERE id = ? AND household_id = ?').bind(account_id, hid).first();
  if (!account) return json({ error: 'Cuenta no encontrada' }, 400);

  const hash = await sha256slice(csvText);
  const existing = await env.DB.prepare('SELECT id FROM import_logs WHERE external_reference = ?').bind(hash).first();
  if (existing) return json({ error: 'Este extracto ya fue importado', hash }, 409);

  const rows = parseBBVACSV(csvText, account_id);
  if (!rows.length) return json({ error: 'No se encontraron transacciones' }, 400);

  await env.DB.batch(rows.map(row =>
    env.DB.prepare(`INSERT INTO transactions (id, account_id, category_id, amount, description, source, status, user_email, transaction_date)
                    VALUES (?, ?, 'cat_other', ?, ?, 'IMPORT', 'PENDING', ?, ?)`)
      .bind(crypto.randomUUID(), row.account_id, row.amount, row.description, email, row.fecha)
  ));
  await env.DB.prepare('INSERT INTO import_logs (id, account_id, external_reference, raw_payload, source_file) VALUES (?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), account_id, hash, csvText.slice(0, 2000), 'bbva_csv').run();

  return json({ ok: true, imported: rows.length });
}

// ── POST /api/import/bbva-pdf ──────────────────────────────────────
async function handleImportBBVAPDF(request, env, email, hid) {
  let pdfText, account_id;
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('multipart/form-data')) {
    const fd = await request.formData();
    account_id = fd.get('account_id');
    pdfText    = fd.get('pdfText');
  } else {
    const body = await request.json();
    ({ pdfText, account_id } = body);
  }

  if (!pdfText || !account_id) return json({ error: 'pdfText y account_id son requeridos' }, 400);

  const account = await env.DB.prepare('SELECT id FROM accounts WHERE id = ? AND household_id = ?').bind(account_id, hid).first();
  if (!account) return json({ error: 'Cuenta no encontrada' }, 400);

  const hash = await sha256slice(pdfText);
  const existing = await env.DB.prepare('SELECT id FROM import_logs WHERE external_reference = ?').bind(hash).first();
  if (existing) return json({ error: 'Este estado de cuenta ya fue importado', hash }, 409);

  const rows = parseBBVAEstadoCuenta(pdfText, account_id);
  if (!rows.length) return json({ error: 'No se encontraron movimientos en el PDF' }, 400);

  await env.DB.batch(rows.map(row =>
    env.DB.prepare(`INSERT INTO transactions (id, account_id, category_id, amount, description, source, status, user_email, transaction_date)
                    VALUES (?, ?, 'cat_other', ?, ?, 'IMPORT', 'PENDING', ?, ?)`)
      .bind(crypto.randomUUID(), row.account_id, row.amount, row.description, email, row.fecha)
  ));
  await env.DB.prepare('INSERT INTO import_logs (id, account_id, external_reference, raw_payload, source_file) VALUES (?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), account_id, hash, pdfText.slice(0, 2000), 'bbva_pdf').run();

  return json({ ok: true, imported: rows.length });
}

// ── Helpers ────────────────────────────────────────────────────────
async function sha256slice(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 32);
}
