import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import { randomInt } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { closePool, execute, query, sql } from './db.mjs';
import { createSupabaseDataClient } from './supabase.mjs';
import { hashPassword, verifyPassword, issueAccessToken, verifyAccessToken } from './security.mjs';
import { createQr, getBankAccount, registerBankAccount, verifyPeyWebhook } from './pey.mjs';

const config = loadConfig();
const supabase = config.supabase ? createSupabaseDataClient(config.supabase) : null;
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.nodeEnv === 'production' ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: { imgSrc: ["'self'", 'data:'] } } }));
if (process.env.VERCEL !== '1') {
  app.use(express.static(process.env.BARRIO_WEB_ROOT || fileURLToPath(new URL('../../prototype/', import.meta.url)), { maxAge: 0, etag: true, lastModified: true }));
}
app.get('/', (_req, res) => res.redirect(302, '/app'));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin) return next();
  const forwardedProto = req.headers['x-forwarded-proto']?.split(',')[0]?.trim();
  const sameOrigin = forwardedProto && req.headers.host && origin === `${forwardedProto}://${req.headers.host}`;
  if (!sameOrigin && !config.corsOrigins.includes(origin)) return res.status(403).json({ error: 'origin_not_allowed' });
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'authorization,content-type,idempotency-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
// A pilot group can share one public IP (school, office, community Wi-Fi).
// Keep registration separate from login and allow at least 100 accounts/IP/window.
const registrationLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });
const jsonParser = express.json({ limit: '64kb', type: 'application/json' });
app.get('/healthz', async (_req, res) => {
  try {
    if (supabase) await supabase.select('barrio_users', { select: 'id', limit: '1' });
    else await query(config.db, 'SELECT 1 AS ok');
    res.json({ ok: true, database: config.databaseProvider });
  }
  catch (error) {
    console.error('healthz_database_check_failed', {
      status: error?.status || null,
      code: error?.code || null,
    });
    res.status(503).json({ ok: false });
  }
});

// Public, non-secret flags used by the interface to avoid collecting bank details
// while Pey is not explicitly enabled on the server.
app.get('/api/v1/runtime/capabilities', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ peyBankAccountRegistrationEnabled: config.paymentMode === 'pey', peyRealQrEnabled: config.paymentMode === 'pey' });
});

function bearer(req, res, next) {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
  const claims = verifyAccessToken(token, config.jwtSecret);
  if (!claims) return res.status(401).json({ error: 'unauthorized' });
  req.user = claims;
  next();
}
function requireRole(role) {
  return (req, res, next) => req.user.roles.includes(role) ? next() : res.status(403).json({ error: 'forbidden' });
}
const id = (value) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value || '');

app.post('/api/v1/auth/register', registrationLimiter, jsonParser, async (req, res, next) => {
  try {
    const { email, phone, password, displayName, biography = null, neighborhood = null, accountType = 'buyer' } = req.body || {};
    if (typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email) || email.length > 256) return res.status(422).json({ error: 'valid_email_required' });
    if (typeof password !== 'string' || password.length < 12 || password.length > 128) return res.status(422).json({ error: 'password_must_be_12_to_128_characters' });
    if (typeof displayName !== 'string' || !displayName.trim() || displayName.length > 100) return res.status(422).json({ error: 'display_name_required' });
    if (biography !== null && (typeof biography !== 'string' || biography.length > 300)) return res.status(422).json({ error: 'invalid_biography' });
    if (neighborhood !== null && (typeof neighborhood !== 'string' || neighborhood.length > 100)) return res.status(422).json({ error: 'invalid_neighborhood' });
    if (!['buyer', 'merchant', 'both'].includes(accountType)) return res.status(422).json({ error: 'invalid_account_type' });
    const zoneRaw = neighborhood?.split(',')[0]?.trim();
    const zoneName = zoneRaw === 'Coyoacán' ? 'Coyoacan' : zoneRaw;
    if (supabase) {
      const zoneRows = zoneName ? await supabase.select('barrio_neighborhoods', { select: 'id', name: `eq.${zoneName}`, limit: '1' }) : [];
      if (neighborhood && !zoneRows[0]) return res.status(422).json({ error: 'unknown_neighborhood' });
      const roles = accountType === 'buyer' ? ['Comprador'] : accountType === 'merchant' ? ['Comercio'] : ['Comprador', 'Comercio'];
      const { salt, hash } = await hashPassword(password);
      const result = await supabase.rpc('barrio_register_user', {
        p_email: email.toLowerCase(), p_phone: phone || null,
        p_password_hash: `\\x${hash.toString('hex')}`, p_password_salt: `\\x${salt.toString('hex')}`,
        p_roles: roles, p_display_name: displayName.trim(), p_biography: biography?.trim() || null,
        p_neighborhood_id: zoneRows[0]?.id ?? null,
      });
      const userId = result.user_id;
      return res.status(201).json({ token: issueAccessToken(userId, roles, config.jwtSecret), user: { userId, roles } });
    }
    const zone = zoneName ? await query(config.db, 'SELECT TOP (1) ColoniaId FROM app.ColoniasPublicas WHERE Nombre=@Nombre', (r,t)=>r.input('Nombre',t.NVarChar(100),zoneName)) : null;
    if (neighborhood && !zone?.recordset?.[0]) return res.status(422).json({error:'unknown_neighborhood'});
    const rolesType = accountType === 'buyer' ? 1 : accountType === 'merchant' ? 2 : 3;
    const { salt, hash } = await hashPassword(password);
    const result = await execute(config.db, 'app.sp_RegistrarUsuario', (r, t) => r
      .input('Correo', t.NVarChar(256), email.toLowerCase())
      .input('Telefono', t.NVarChar(20), phone || null)
      .input('HashContrasena', t.VarBinary(256), hash)
      .input('SalContrasena', t.VarBinary(64), salt)
      .input('TipoUso', t.TinyInt, rolesType)
      .input('NombreMostrar', t.NVarChar(100), displayName.trim())
      .input('ColoniaId', t.Int, zone?.recordset?.[0]?.ColoniaId ?? null)
      .input('Biografia', t.NVarChar(300), biography?.trim() || null)
      .output('UsuarioId', t.UniqueIdentifier));
    const userId = result.output.UsuarioId;
    const roles = accountType === 'buyer' ? ['Comprador'] : accountType === 'merchant' ? ['Comercio'] : ['Comprador','Comercio'];
    return res.status(201).json({ token: issueAccessToken(userId, roles, config.jwtSecret), user: { userId, roles } });
  } catch (err) { next(err); }
});

app.post('/api/v1/auth/login', authLimiter, jsonParser, async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.toLowerCase() : '';
    const password = req.body?.password;
    if (!email || typeof password !== 'string') return res.status(422).json({ error: 'email_and_password_required' });
    if (supabase) {
      const rows = await supabase.select('barrio_users', { select: 'id,roles,password_hash,password_salt', email: `eq.${email}`, active: 'eq.true', limit: '1' });
      const record = rows[0];
      const fromBytea = (value) => Buffer.from(String(value || '').replace(/^\\x/, ''), 'hex');
      if (!record || !await verifyPassword(password, fromBytea(record.password_salt), fromBytea(record.password_hash))) return res.status(401).json({ error: 'invalid_credentials' });
      return res.json({ token: issueAccessToken(record.id, record.roles, config.jwtSecret), user: { userId: record.id, roles: record.roles } });
    }
    const result = await execute(config.db, 'app.sp_ObtenerCredencialLogin', (r, t) => r.input('Correo', t.NVarChar(256), email));
    const record = result.recordset?.[0];
    if (!record || !await verifyPassword(password, record.SalContrasena, record.HashContrasena)) return res.status(401).json({ error: 'invalid_credentials' });
    const roles = String(record.RolesCsv || '').split(',').filter(Boolean);
    return res.json({ token: issueAccessToken(record.UsuarioId, roles, config.jwtSecret), user: { userId: record.UsuarioId, roles } });
  } catch (err) { next(err); }
});

app.get('/api/v1/auth/me', bearer, (req, res) => res.json({ userId: req.user.sub, roles: req.user.roles }));

app.get('/api/v1/merchants', async (_req, res, next) => {
  try {
    // Public directory data should always reflect the latest merchant record.
    res.setHeader('Cache-Control', 'no-store');
    if (supabase) {
      const merchants = await supabase.select('barrio_merchants', {
        select: 'id,name,description,neighborhood_id,show_in_directory',
        active: 'eq.true', show_in_directory: 'eq.true', order: 'name.asc', limit: '200',
      });
      if (!merchants.length) return res.json({ items: [] });
      const ids = merchants.map((merchant) => merchant.id);
      const inFilter = `in.(${ids.join(',')})`;
      const [zones, assignments, categories, enabledMethods, methodCatalog] = await Promise.all([
        supabase.select('barrio_neighborhoods', { select: 'id,name' }),
        supabase.select('barrio_merchant_categories', { select: 'merchant_id,category_id', merchant_id: inFilter }),
        supabase.select('barrio_categories', { select: 'id,name', active: 'eq.true' }),
        supabase.select('barrio_merchant_payment_methods', { select: 'merchant_id,method_code', merchant_id: inFilter, selected: 'eq.true', enabled: 'eq.true' }),
        supabase.select('barrio_payment_methods', { select: 'code,name' }),
      ]);
      const zoneById = new Map(zones.map((zone) => [String(zone.id), zone.name]));
      const categoryById = new Map(categories.map((category) => [String(category.id), category.name]));
      const categoryByMerchant = new Map(assignments.map((row) => [row.merchant_id, categoryById.get(String(row.category_id)) || 'Otros']));
      const methodNameByCode = new Map(methodCatalog.map((method) => [method.code, method.name]));
      const methodsByMerchant = new Map();
      for (const row of enabledMethods) {
        const list = methodsByMerchant.get(row.merchant_id) || [];
        list.push({ code: row.method_code, name: methodNameByCode.get(row.method_code) || row.method_code });
        methodsByMerchant.set(row.merchant_id, list);
      }
      const categoryPresentation = {
        Cafeterias: { kind: 'Cafés', type: 'Cafetería', emoji: '☕', art: 'cafe' },
        Alimentos: { kind: 'Todos', type: 'Alimentos', emoji: '🥖', art: 'cafe' },
        Tiendas: { kind: 'Tiendas', type: 'Tienda', emoji: '🏪', art: 'flowers' },
        Servicios: { kind: 'Servicios', type: 'Servicios', emoji: '🔧', art: 'tools' },
        Flores: { kind: 'Tiendas', type: 'Flores y plantas', emoji: '🌷', art: 'flowers' },
        Belleza: { kind: 'Servicios', type: 'Belleza', emoji: '✂️', art: 'tools' },
        Hogar: { kind: 'Tiendas', type: 'Hogar', emoji: '🏠', art: 'flowers' },
        Otros: { kind: 'Todos', type: 'Comercio local', emoji: '🏬', art: 'cafe' },
      };
      return res.json({ items: merchants.map((merchant) => {
        const category = categoryByMerchant.get(merchant.id) || 'Otros';
        return {
          id: merchant.id, merchantId: merchant.id, name: merchant.name,
          description: merchant.description || '', about: merchant.description || 'Comercio local de tu barrio.',
          zone: zoneById.get(String(merchant.neighborhood_id)) || '',
          category, showInDirectory: merchant.show_in_directory,
          ...categoryPresentation[category], followers: '—', posts: '—',
          paymentMethods: methodsByMerchant.get(merchant.id) || [],
        };
      }) });
    }
    const result = await query(config.db, 'SELECT TOP (200) ComercioId AS id, NombreNegocio AS name, Descripcion AS description, Colonia, Latitud AS latitude, Longitud AS longitude FROM app.PerfilPublicoComercio ORDER BY NombreNegocio');
    res.json({ items: result.recordset });
  } catch (err) { next(err); }
});
app.get('/api/v1/merchant/profiles', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'multiple_merchant_profiles_require_supabase_mvp' });
    const merchants = await supabase.select('barrio_merchants', { select: 'id,name,description,neighborhood_id,show_in_directory,created_at', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', order: 'created_at.asc' });
    const items = await Promise.all(merchants.map(async (merchant) => {
      const [zones, merchantCategories, accounts, attempts] = await Promise.all([
        supabase.select('barrio_neighborhoods', { select: 'name', id: `eq.${merchant.neighborhood_id}`, limit: '1' }),
        supabase.select('barrio_merchant_categories', { select: 'category_id', merchant_id: `eq.${merchant.id}`, limit: '1' }),
        supabase.select('barrio_pey_bank_accounts', { select: 'clabe_last4,codi_status', merchant_id: `eq.${merchant.id}`, limit: '1' }),
        supabase.select('barrio_pey_registration_attempts', { select: 'clabe_last4,state,created_at', merchant_id: `eq.${merchant.id}`, order: 'created_at.desc', limit: '1' }),
      ]);
      const categories = merchantCategories[0] ? await supabase.select('barrio_categories', { select: 'name', id: `eq.${merchantCategories[0].category_id}`, limit: '1' }) : [];
      const unresolvedAttempt = !accounts[0] ? attempts.find((attempt) => ['SOLICITANDO','INCIERTA'].includes(attempt.state)) : null;
      return { merchantId: merchant.id, name: merchant.name, description: merchant.description, neighborhood: zones[0]?.name || '', category: categories[0]?.name || '', showInDirectory: merchant.show_in_directory, peyStatus: accounts[0]?.codi_status || null, peyAttemptState: unresolvedAttempt?.state || null, clabeLast4: accounts[0]?.clabe_last4 || unresolvedAttempt?.clabe_last4 || null };
    }));
    res.json({ items, limit: 5 });
  } catch (err) { next(err); }
});
app.get('/api/v1/merchants/:merchantId/products', async (req, res, next) => {
  try {
    if (!id(req.params.merchantId)) return res.status(400).json({ error: 'invalid_merchant_id' });
    if (supabase) {
      res.setHeader('Cache-Control', 'no-store');
      const merchant = await supabase.select('barrio_merchants', { select: 'id', id: `eq.${req.params.merchantId}`, active: 'eq.true', show_in_directory: 'eq.true', limit: '1' });
      if (!merchant[0]) return res.json({ items: [] });
      const products = await supabase.select('barrio_products', {
        select: 'id,merchant_id,name,description,category,price_mxn,stock',
        merchant_id: `eq.${req.params.merchantId}`, active: 'eq.true', stock: 'gt.0', order: 'name.asc', limit: '200',
      });
      return res.json({ items: products.map((product) => ({ ...product, merchantId: product.merchant_id, priceMXN: Number(product.price_mxn), emoji: '🛍️' })) });
    }
    const result = await query(config.db, `SELECT ProductoId AS id, ComercioId AS merchantId, Nombre AS name, DescripcionCorta AS description, Precio AS priceMXN, Existencias AS stock FROM app.ProductosPublicos WHERE ComercioId=@merchantId AND Existencias>0 ORDER BY Nombre`, (r, t) => r.input('merchantId', t.UniqueIdentifier, req.params.merchantId));
    res.json({ items: result.recordset });
  } catch (err) { next(err); }
});

app.post('/api/v1/merchant/profile', bearer, requireRole('Comercio'), jsonParser, async (req, res, next) => {
  try {
    const { name, description = null, neighborhood = null, category = null, showInDirectory = true, creationKey } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 150) return res.status(422).json({ error: 'valid_business_name_required' });
    if (description !== null && (typeof description !== 'string' || description.length > 500)) return res.status(422).json({ error: 'invalid_description' });
    if (typeof neighborhood !== 'string' || typeof category !== 'string') return res.status(422).json({ error: 'neighborhood_and_category_required' });
    if (typeof showInDirectory !== 'boolean') return res.status(422).json({ error: 'invalid_directory_preference' });
    if (supabase) {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(creationKey || '')) return res.status(422).json({ error: 'valid_creation_key_required' });
      const zoneName = neighborhood.split(',')[0].trim().replace('Coyoacán', 'Coyoacan');
      const categoryAliases = {'Cafetería':'Cafeterias','Cafeteria':'Cafeterias','Restaurante':'Alimentos','Panadería':'Alimentos','Flores y plantas':'Flores','Tienda':'Tiendas','Servicios':'Servicios','Otro':'Otros'};
      const categoryName = categoryAliases[category] || category;
      const [zones, categories] = await Promise.all([
        supabase.select('barrio_neighborhoods', { select: 'id', name: `eq.${zoneName}`, limit: '1' }),
        supabase.select('barrio_categories', { select: 'id', name: `eq.${categoryName}`, active: 'eq.true', limit: '1' }),
      ]);
      if (!zones[0] || !categories[0]) return res.status(422).json({ error: 'unknown_neighborhood_or_category' });
      const result = await supabase.rpc('barrio_create_merchant_idempotent', {
        p_user_id: req.user.sub, p_name: name.trim(), p_description: description?.trim() || null,
        p_neighborhood_id: zones[0].id, p_category_id: categories[0].id, p_show_in_directory: showInDirectory, p_creation_key: creationKey,
      });
      return res.status(201).json({ merchantId: result.merchant_id, name: name.trim(), category: categoryName, neighborhood: zoneName, showInDirectory });
    }
    const zoneRaw=neighborhood.split(',')[0].trim();
    const zoneName=zoneRaw==='Coyoacán'?'Coyoacan':zoneRaw;
    const zone=await query(config.db,'SELECT TOP (1) ColoniaId FROM app.ColoniasPublicas WHERE Nombre=@Nombre',(r,t)=>r.input('Nombre',t.NVarChar(100),zoneName));
    const categoryAliases={'Cafetería':'Cafeterias','Cafeteria':'Cafeterias','Restaurante':'Alimentos','Panadería':'Alimentos','Flores y plantas':'Flores','Tienda':'Tiendas','Servicios':'Servicios','Otro':'Otros'};
    const categoryName=categoryAliases[category]||category;
    const categoryRow=await query(config.db,'SELECT TOP (1) CategoriaId FROM app.CategoriasPublicas WHERE Nombre=@Nombre',(r,t)=>r.input('Nombre',t.NVarChar(50),categoryName));
    if (!zone.recordset?.[0] || !categoryRow.recordset?.[0]) return res.status(422).json({error:'unknown_neighborhood_or_category'});
    const result = await execute(config.db, 'app.sp_CrearComercioPropio', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('NombreNegocio', t.NVarChar(150), name.trim())
      .input('Descripcion', t.NVarChar(500), description)
      .input('ColoniaId', t.Int, zone.recordset[0].ColoniaId)
      .input('CategoriaId', t.Int, categoryRow.recordset[0].CategoriaId)
      .input('MostrarEnDirectorio', t.Bit, showInDirectory)
      .output('ComercioId', t.UniqueIdentifier));
    res.status(201).json({ merchantId: result.output.ComercioId, name: name.trim(), category: categoryName, neighborhood: zoneName, showInDirectory });
  } catch (err) { next(err); }
});

app.get('/api/v1/merchant/payment-methods', bearer, requireRole('Comercio'), async (req,res,next)=>{
  try {
    if (supabase) {
      const requestedId = req.query.merchantId;
      if (requestedId && !id(requestedId)) return res.status(400).json({ error: 'invalid_merchant_id' });
      const merchants = await supabase.select('barrio_merchants', { select: 'id', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', ...(requestedId ? { id: `eq.${requestedId}` } : {}), order: 'created_at.asc', limit: '1' });
      if (!merchants[0]) return res.json({ items: [] });
      const rows = await supabase.select('barrio_merchant_payment_methods', { select: 'method_code,selected,enabled,configuration_status', merchant_id: `eq.${merchants[0].id}` });
      const methods = await supabase.select('barrio_payment_methods', { select: 'code,name,sort_order', order: 'sort_order.asc' });
      const mapped = new Map(rows.map((row) => [row.method_code, row]));
      return res.json({ items: methods.filter((method) => mapped.has(method.code)).map((method) => ({ Codigo: method.code, Nombre: method.name, Solicitado: mapped.get(method.code).selected, EstaHabilitado: mapped.get(method.code).enabled, EstadoConfiguracion: mapped.get(method.code).configuration_status })) });
    }
    const result=await execute(config.db,'app.sp_ObtenerMetodosPagoPropios',(r,t)=>r.input('UsuarioId',t.UniqueIdentifier,req.user.sub)); res.json({items:result.recordset||[]});
  }
  catch(err){next(err)}
});
app.put('/api/v1/merchant/payment-methods', bearer, requireRole('Comercio'), jsonParser, async(req,res,next)=>{
  try {
    const methods=req.body?.methods;
    const allowed=['EFECTIVO','PEY_CODI','SPEI','TARJETA','WALLETS','NFC','CRIPTO_HBAR'];
    if(!Array.isArray(methods)||methods.length<1||methods.length>allowed.length||methods.some(m=>!allowed.includes(m?.code)||typeof m.selected!=='boolean')||new Set(methods.map(m=>m.code)).size!==methods.length) return res.status(422).json({error:'invalid_payment_methods'});
    if (supabase) {
      const merchantId = req.body?.merchantId;
      if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
      const saved = await supabase.rpc('barrio_save_payment_methods_for_merchant', { p_user_id: req.user.sub, p_merchant_id: merchantId, p_methods: methods });
      // Saving preferences must not reset a previously verified Pey account
      // to REQUIERE_PEY. The SQL preference function predates account-status
      // synchronization, so re-apply the authoritative status returned by Pey.
      const account = await supabase.select('barrio_pey_bank_accounts', {
        select: 'codi_status', merchant_id: `eq.${merchantId}`, limit: '1',
      });
      if (account[0]) {
        const selected = methods.find((method) => method.code === 'PEY_CODI')?.selected === true;
        const status = String(account[0].codi_status || '').toUpperCase();
        await supabase.upsert('barrio_merchant_payment_methods', {
          merchant_id: merchantId, method_code: 'PEY_CODI', selected,
          enabled: selected && status === 'ACTIVE',
          configuration_status: !selected ? 'PENDIENTE' : status === 'ACTIVE' ? 'DISPONIBLE' : status === 'ERROR' ? 'REQUIERE_PEY' : 'PENDIENTE',
          updated_at: new Date().toISOString(),
        }, 'merchant_id,method_code');
      }
      return res.json({ items: saved });
    }
    const result=await execute(config.db,'app.sp_GuardarMetodosPagoPropios',(r,t)=>r.input('UsuarioId',t.UniqueIdentifier,req.user.sub).input('MetodosJson',t.NVarChar(sql.MAX),JSON.stringify(methods)));
    res.json({items:result.recordset||[]});
  } catch(err){next(err)}
});

app.get('/api/v1/merchant/profile', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (supabase) {
      const requestedId = req.query.merchantId;
      if (requestedId && !id(requestedId)) return res.status(400).json({ error: 'invalid_merchant_id' });
      const merchants = await supabase.select('barrio_merchants', { select: 'id,name,description,neighborhood_id,show_in_directory', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', ...(requestedId ? { id: `eq.${requestedId}` } : {}), order: 'created_at.asc', limit: '1' });
      const merchant = merchants[0];
      if (!merchant) return res.status(404).json({ error: 'merchant_profile_required' });
      const [zones, categories] = await Promise.all([
        supabase.select('barrio_neighborhoods', { select: 'name', id: `eq.${merchant.neighborhood_id}`, limit: '1' }),
        supabase.select('barrio_merchant_categories', { select: 'category_id', merchant_id: `eq.${merchant.id}`, limit: '1' }),
      ]);
      const category = categories[0] ? await supabase.select('barrio_categories', { select: 'name', id: `eq.${categories[0].category_id}`, limit: '1' }) : [];
      return res.json({ merchant: { ComercioId: merchant.id, NombreNegocio: merchant.name, Descripcion: merchant.description, Colonia: zones[0]?.name, Categoria: category[0]?.name, MostrarEnDirectorio: merchant.show_in_directory } });
    }
    const result = await execute(config.db, 'app.sp_ObtenerComercioPropio', (r, t) => r.input('UsuarioId', t.UniqueIdentifier, req.user.sub));
    const merchant = result.recordset?.[0];
    if (!merchant) return res.status(404).json({ error: 'merchant_profile_required' });
    res.json({ merchant });
  } catch (err) { next(err); }
});

app.post('/api/v1/merchant/products', bearer, requireRole('Comercio'), jsonParser, async (req, res, next) => {
  try {
    const { merchantId: requestedMerchantId, name, description = null, category = 'Otros', priceMXN, stock } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 150 || !Number.isFinite(priceMXN) || priceMXN <= 0 || !Number.isInteger(stock) || stock < 0) return res.status(422).json({ error: 'invalid_product' });
    if (description !== null && (typeof description !== 'string' || description.length > 160)) return res.status(422).json({ error: 'invalid_description' });
    if (typeof category !== 'string' || !category.trim() || category.length > 60) return res.status(422).json({ error: 'invalid_category' });
    if (supabase) {
      if (!id(requestedMerchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
      const merchants = await supabase.select('barrio_merchants', { select: 'id', id: `eq.${requestedMerchantId}`, owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', limit: '1' });
      if (!merchants[0]) return res.status(404).json({ error: 'merchant_profile_required' });
      const created = await supabase.insert('barrio_products', { merchant_id: requestedMerchantId, name: name.trim(), description: description?.trim() || null, category: category.trim(), price_mxn: priceMXN, stock, active: true });
      return res.status(201).json({ productId: created[0].id, merchantId: requestedMerchantId });
    }
    const merchant = await execute(config.db, 'app.sp_ObtenerComercioPropio', (r, t) => r.input('UsuarioId', t.UniqueIdentifier, req.user.sub));
    const merchantId = merchant.recordset?.[0]?.ComercioId;
    if (!merchantId) return res.status(409).json({ error: 'merchant_profile_required' });
    const created = await execute(config.db, 'app.sp_GuardarProductoPropio', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('ComercioId', t.UniqueIdentifier, merchantId)
      .input('Nombre', t.NVarChar(150), name.trim())
      .input('DescripcionCorta', t.NVarChar(160), description)
      .input('Precio', t.Decimal(10, 2), priceMXN)
      .input('Existencias', t.Int, stock)
      .output('ProductoId', t.UniqueIdentifier));
    res.status(201).json({ productId: created.output.ProductoId, merchantId });
  } catch (err) { next(err); }
});

app.get('/api/v1/merchant/products', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'merchant_products_require_supabase_mvp' });
    const merchantId = req.query.merchantId;
    if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
    const merchants = await supabase.select('barrio_merchants', { select: 'id', id: `eq.${merchantId}`, owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', limit: '1' });
    if (!merchants[0]) return res.status(404).json({ error: 'merchant_profile_required' });
    const products = await supabase.select('barrio_products', { select: 'id,merchant_id,name,description,category,price_mxn,stock,active', merchant_id: `eq.${merchantId}`, order: 'created_at.desc', limit: '200' });
    return res.json({ items: products.map((product) => ({ id: product.id, merchantId: product.merchant_id, name: product.name, description: product.description || '', category: product.category, price: Number(product.price_mxn), stock: product.stock, active: product.active, status: product.stock > 0 ? 'En existencia' : 'Agotado', emoji: '🛍️' })) });
  } catch (err) { next(err); }
});

app.put('/api/v1/merchant/products/:productId', bearer, requireRole('Comercio'), jsonParser, async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'merchant_products_require_supabase_mvp' });
    if (!id(req.params.productId)) return res.status(400).json({ error: 'invalid_product_id' });
    const { merchantId, name, description = null, category = 'Otros', priceMXN, stock, active = true } = req.body || {};
    if (!id(merchantId || '') || typeof name !== 'string' || !name.trim() || name.length > 150 || !Number.isFinite(priceMXN) || priceMXN <= 0 || !Number.isInteger(stock) || stock < 0 || typeof active !== 'boolean') return res.status(422).json({ error: 'invalid_product' });
    if (description !== null && (typeof description !== 'string' || description.length > 160)) return res.status(422).json({ error: 'invalid_description' });
    const merchants = await supabase.select('barrio_merchants', { select: 'id', id: `eq.${merchantId}`, owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', limit: '1' });
    if (!merchants[0]) return res.status(404).json({ error: 'merchant_profile_required' });
    const updated = await supabase.update('barrio_products', { id: `eq.${req.params.productId}`, merchant_id: `eq.${merchantId}` }, { name: name.trim(), description: description?.trim() || null, category: String(category).slice(0,60), price_mxn: priceMXN, stock, active, updated_at: new Date().toISOString() });
    if (!updated?.length) return res.status(404).json({ error: 'product_not_found' });
    return res.json({ productId: req.params.productId, merchantId });
  } catch (err) { next(err); }
});

app.post('/api/v1/merchant/bank-account', bearer, requireRole('Comercio'), authLimiter, jsonParser, async (req, res, next) => {
  try {
    if (config.paymentMode !== 'pey') return res.status(503).json({ error: 'pey_onboarding_disabled_in_simulation_mode' });
    const { merchantId, clabe, name, entity, taxId, alias, idempotencyKey } = req.body || {};
    if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
    if (!/^\d{18}$/.test(clabe || '') || typeof name !== 'string' || !name.trim() || !['business', 'person'].includes(entity)) return res.status(422).json({ error: 'invalid_bank_account' });
    if (typeof idempotencyKey !== 'string' || idempotencyKey.length < 16 || idempotencyKey.length > 100) return res.status(422).json({ error: 'idempotency_key_required' });
    if (taxId != null && (typeof taxId !== 'string' || taxId.length > 20)) return res.status(422).json({ error: 'invalid_tax_id' });
    if (alias != null && (typeof alias !== 'string' || alias.length > 100)) return res.status(422).json({ error: 'invalid_alias' });
    const started = supabase
      ? await supabase.rpc('barrio_begin_pey_registration_for_merchant', { p_user_id: req.user.sub, p_merchant_id: merchantId, p_key: idempotencyKey, p_clabe_last4: clabe.slice(-4) }).then((row) => ({ recordset: [{ DebeRegistrar: row.should_register, ComercioId: row.merchant_id, PeyBankAccountId: row.bank_account_id, CodiStatus: row.status, ClabeUltimos4: row.clabe_last4, Estado: row.state }] }))
      : await execute(config.db, 'app.sp_IniciarAltaCuentaPey', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('IdempotencyKey', t.NVarChar(100), idempotencyKey)
      .input('ClabeUltimos4', t.Char(4), clabe.slice(-4)));
    const attempt = started.recordset?.[0];
    if (!attempt?.DebeRegistrar) {
      if (attempt?.PeyBankAccountId) return res.status(200).json({ bankAccountId: attempt.PeyBankAccountId, status: attempt.CodiStatus, clabeLast4: attempt.ClabeUltimos4 });
      return res.status(409).json({ error: 'bank_account_registration_requires_reconciliation', status: attempt?.Estado || 'UNKNOWN' });
    }
    let account;
    try {
      account = await registerBankAccount({ clabe, name: name.trim(), entity, taxId, alias }, config.peyApiKey, { allowProduction: config.paymentMode === 'pey' });
    } catch (providerError) {
      const definitelyRejected = [400, 401, 403, 404, 409, 422, 429].includes(providerError.status);
      if (supabase && definitelyRejected) await supabase.rpc('barrio_mark_pey_attempt_rejected', { p_user_id: req.user.sub, p_merchant_id: attempt.ComercioId, p_key: idempotencyKey });
      else if (supabase) await supabase.rpc('barrio_mark_pey_attempt_uncertain', { p_user_id: req.user.sub, p_merchant_id: attempt.ComercioId, p_key: idempotencyKey });
      else await execute(config.db, 'app.sp_MarcarAltaCuentaPeyIncierta', (r, t) => r
        .input('ComercioId', t.UniqueIdentifier, attempt.ComercioId)
        .input('IdempotencyKey', t.NVarChar(100), idempotencyKey));
      throw providerError;
    }
    if (!account.id) {
      if (supabase) await supabase.rpc('barrio_mark_pey_attempt_uncertain', { p_user_id: req.user.sub, p_merchant_id: attempt.ComercioId, p_key: idempotencyKey });
      else await execute(config.db, 'app.sp_MarcarAltaCuentaPeyIncierta', (r, t) => r
        .input('ComercioId', t.UniqueIdentifier, attempt.ComercioId)
        .input('IdempotencyKey', t.NVarChar(100), idempotencyKey));
      return res.status(502).json({ error: 'pey_invalid_response' });
    }
    const saved = supabase
      ? { recordset: [await supabase.rpc('barrio_finish_pey_registration', { p_user_id: req.user.sub, p_merchant_id: attempt.ComercioId, p_key: idempotencyKey, p_pey_account_id: account.id, p_clabe_last4: clabe.slice(-4), p_status: String(account.codiStatus || 'PENDING').toUpperCase() }).then((row) => ({ CodiStatus: row.status }))] }
      : await execute(config.db, 'app.sp_GuardarCuentaPeyComercio', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('ComercioId', t.UniqueIdentifier, attempt.ComercioId)
      .input('IdempotencyKey', t.NVarChar(100), idempotencyKey)
      .input('PeyBankAccountId', t.NVarChar(40), account.id)
      .input('ClabeUltimos4', t.Char(4), clabe.slice(-4))
      .input('CodiStatus', t.NVarChar(20), String(account.codiStatus || 'PENDING').toUpperCase())
      );
    if (!supabase) await execute(config.db, 'app.sp_SincronizarMetodoPey', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('CodiStatus', t.NVarChar(20), String(saved.recordset?.[0]?.CodiStatus || account.codiStatus || 'PENDING').toUpperCase()));
    res.status(202).json({ bankAccountId: account.id, status: saved.recordset?.[0]?.CodiStatus || account.codiStatus || 'PENDING', clabeLast4: clabe.slice(-4) });
  } catch (err) { next(err); }
});

app.get('/api/v1/merchant/bank-account/status', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (config.paymentMode !== 'pey') return res.status(503).json({ error: 'pey_onboarding_disabled_in_simulation_mode' });
    let account;
    if (supabase) {
      const merchantId = req.query.merchantId;
      if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
      const merchants = await supabase.select('barrio_merchants', { select: 'id', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', id: `eq.${merchantId}`, limit: '1' });
      if (merchants[0]) {
        const accounts = await supabase.select('barrio_pey_bank_accounts', { select: 'pey_bank_account_id,clabe_last4,codi_status', merchant_id: `eq.${merchants[0].id}`, limit: '1' });
        account = accounts[0] ? { PeyBankAccountId: accounts[0].pey_bank_account_id, ClabeUltimos4: accounts[0].clabe_last4, CodiStatus: accounts[0].codi_status, ComercioId: merchants[0].id } : null;
      }
    } else {
      const result = await execute(config.db, 'app.sp_ObtenerCuentaPeyPropia', (r, t) => r.input('UsuarioId', t.UniqueIdentifier, req.user.sub));
      account = result.recordset?.[0];
    }
    if (!account) return res.status(404).json({ error: 'bank_account_not_registered' });
    const latest = await getBankAccount(account.PeyBankAccountId, config.peyApiKey, { allowProduction: config.paymentMode === 'pey' });
    const status = String(latest.codiStatus || account.CodiStatus).toUpperCase();
    if (supabase) {
      await supabase.update('barrio_pey_bank_accounts', { merchant_id: `eq.${account.ComercioId}` }, { codi_status: status, updated_at: new Date().toISOString() });
      await supabase.upsert('barrio_merchant_payment_methods', { merchant_id: account.ComercioId, method_code: 'PEY_CODI', selected: true, enabled: status === 'ACTIVE', configuration_status: status === 'ACTIVE' ? 'DISPONIBLE' : status === 'ERROR' ? 'REQUIERE_PEY' : 'PENDIENTE', updated_at: new Date().toISOString() }, 'merchant_id,method_code');
    } else await execute(config.db, 'app.sp_ActualizarEstadoCuentaPey', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('PeyBankAccountId', t.NVarChar(40), account.PeyBankAccountId)
      .input('CodiStatus', t.NVarChar(20), status));
    if (!supabase) await execute(config.db, 'app.sp_SincronizarMetodoPey', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('CodiStatus', t.NVarChar(20), status));
    res.json({ bankAccountId: account.PeyBankAccountId, clabeLast4: account.ClabeUltimos4, status });
  } catch (err) { next(err); }
});

app.post('/api/v1/merchant/codi/qr', bearer, requireRole('Comercio'), authLimiter, jsonParser, async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'manual_codi_qr_requires_supabase' });
    if (config.paymentMode !== 'pey') return res.status(503).json({ error: 'pey_live_payments_not_enabled' });
    const amount = Number(req.body?.amount);
    const merchantId = req.body?.merchantId;
    const concept = typeof req.body?.concept === 'string' ? req.body.concept.trim() : '';
    const key = req.get('Idempotency-Key') || req.body?.idempotencyKey;
    if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000 || Math.round(amount * 100) !== amount * 100) return res.status(422).json({ error: 'valid_amount_required' });
    if (!concept || concept.length > 100) return res.status(422).json({ error: 'valid_concept_required' });
    if (typeof key !== 'string' || key.length < 16 || key.length > 100) return res.status(422).json({ error: 'idempotency_key_required' });
    const numRef = String(randomInt(0, 10000000)).padStart(7, '0');
    const started = await supabase.rpc('barrio_begin_pey_qr', {
      p_user_id: req.user.sub, p_merchant_id: merchantId, p_key: key, p_amount: amount, p_concept: concept, p_num_ref: numRef,
    });
    if (!started.should_create) {
      if (started.status === 'PENDING' && started.qr_string) {
        return res.json({ requestId: started.request_id, qrId: started.pey_qr_id, qrString: started.qr_string,
          qrImageDataUrl: await QRCode.toDataURL(started.qr_string), amountMXN: Number(started.amount_mxn),
          concept: started.concept, status: started.status, createdAt: started.created_at, expiresAt: started.expires_at });
      }
      return res.status(409).json({ error: 'qr_request_requires_reconciliation', requestId: started.request_id, status: started.status });
    }
    let qr;
    try {
      qr = await createQr({ amount, concept, expiration: 600, numRef: started.num_ref, bankAccountId: started.bank_account_id,
        metadata: { barrioQrRequestId: started.request_id } }, config.peyApiKey, { allowProduction: true });
      if (!qr?.id || !qr?.qrString) throw new Error('Pey response did not include QR data');
      const expiresAt = new Date(Date.now() + 600000).toISOString();
      const saved = await supabase.rpc('barrio_finish_pey_qr', {
        p_user_id: req.user.sub, p_request_id: started.request_id, p_pey_qr_id: qr.id,
        p_qr_string: qr.qrString, p_expires_at: expiresAt,
      });
      return res.status(201).json({ requestId: saved.id, qrId: saved.pey_qr_id, qrString: saved.qr_string,
        qrImageDataUrl: await QRCode.toDataURL(saved.qr_string), amountMXN: Number(saved.amount_mxn),
        concept: saved.concept, status: saved.status, createdAt: saved.created_at, expiresAt: saved.expires_at });
    } catch (providerError) {
      await supabase.rpc('barrio_mark_pey_qr_uncertain', { p_user_id: req.user.sub, p_request_id: started.request_id });
      throw providerError;
    }
  } catch (err) { next(err); }
});

app.get('/api/v1/merchant/codi/qr/latest', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'manual_codi_qr_requires_supabase' });
    const merchantId = req.query.merchantId;
    if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
    const merchants = await supabase.select('barrio_merchants', { select: 'id', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', id: `eq.${merchantId}`, limit: '1' });
    if (!merchants[0]) return res.status(404).json({ error: 'merchant_profile_required' });
    const rows = await supabase.select('barrio_pey_qr_requests', { select: 'id,pey_qr_id,qr_string,amount_mxn,concept,status,created_at,expires_at,paid_at', merchant_id: `eq.${merchants[0].id}`, order: 'created_at.desc', limit: '1' });
    const item = rows[0];
    if (!item) return res.status(404).json({ error: 'qr_not_found' });
    if (item.status === 'PENDING' && item.expires_at && new Date(item.expires_at).getTime() <= Date.now()) {
      await supabase.update('barrio_pey_qr_requests', { id: `eq.${item.id}`, status: 'eq.PENDING' }, { status: 'EXPIRED' });
      item.status = 'EXPIRED';
    }
    res.json({ requestId: item.id, qrId: item.pey_qr_id, qrString: item.qr_string,
      qrImageDataUrl: item.qr_string ? await QRCode.toDataURL(item.qr_string) : null,
      amountMXN: Number(item.amount_mxn), concept: item.concept, status: item.status,
      createdAt: item.created_at, expiresAt: item.expires_at, paidAt: item.paid_at });
  } catch (err) { next(err); }
});

app.post('/api/v1/orders/checkout', bearer, requireRole('Comprador'), authLimiter, jsonParser, async (req, res, next) => {
  try {
    if (supabase) {
      if (config.paymentMode !== 'pey') return res.status(503).json({ error: 'pey_live_payments_not_enabled' });
      const { merchantId, items, deliveryMethod = 'RECOGER', deliveryAddress = null } = req.body || {};
      const key = req.get('Idempotency-Key');
      if (!id(merchantId || '') || !Array.isArray(items) || items.length < 1 || items.length > 50 || items.some((item) => !id(item?.productId || '') || !Number.isInteger(item?.quantity) || item.quantity < 1 || item.quantity > 100)) return res.status(422).json({ error: 'invalid_checkout' });
      if (!key || key.length < 16 || key.length > 100) return res.status(422).json({ error: 'idempotency_key_required' });
      if (!['RECOGER','ENTREGA_LOCAL'].includes(deliveryMethod) || (deliveryMethod === 'ENTREGA_LOCAL' && (typeof deliveryAddress !== 'string' || !deliveryAddress.trim() || deliveryAddress.length > 300))) return res.status(422).json({ error: 'invalid_delivery_method' });
      const created = await supabase.rpc('barrio_create_checkout_order', {
        p_user_id: req.user.sub, p_merchant_id: merchantId, p_key: key, p_items: items,
        p_delivery_method: deliveryMethod, p_delivery_address: deliveryAddress,
      });
      const numRef = String(randomInt(0, 10000000)).padStart(7, '0');
      const qrKey = `checkout-${created.order_id}`;
      const started = await supabase.rpc('barrio_begin_checkout_qr', { p_user_id: req.user.sub, p_order_id: created.order_id, p_key: qrKey, p_num_ref: numRef });
      if (!started.should_create) {
        if (started.status === 'PAID') return res.status(200).json({ orderId: created.order_id, merchantId, amountMXN: Number(started.amount_mxn), paymentStatus: 'PAGADO', expiresAt: started.expires_at });
        if (started.status === 'PENDING' && started.qr_string) return res.status(200).json({ orderId: created.order_id, merchantId, amountMXN: Number(started.amount_mxn), qrImageDataUrl: await QRCode.toDataURL(started.qr_string), paymentStatus: 'PENDIENTE', expiresAt: started.expires_at });
        return res.status(409).json({ error: 'checkout_requires_reconciliation', orderId: created.order_id, paymentStatus: started.status });
      }
      try {
        const qr = await createQr({ amount: Number(created.total_mxn), concept: `BARRIO ${String(created.order_id).slice(0,8)}`, expiration: 600, numRef: started.num_ref, bankAccountId: started.bank_account_id, metadata: { barrioQrRequestId: started.request_id, barrioOrderId: created.order_id } }, config.peyApiKey, { allowProduction: true });
        if (!qr?.id || !qr?.qrString) throw new Error('Pey response did not include QR data');
        const expiresAt = new Date(Date.now() + 600000).toISOString();
        const saved = await supabase.rpc('barrio_finish_checkout_qr', { p_user_id: req.user.sub, p_request_id: started.request_id, p_pey_qr_id: qr.id, p_qr_string: qr.qrString, p_expires_at: expiresAt });
        return res.status(201).json({ orderId: created.order_id, merchantId, amountMXN: Number(saved.amount_mxn), qrImageDataUrl: await QRCode.toDataURL(saved.qr_string), paymentStatus: 'PENDIENTE', expiresAt: saved.expires_at });
      } catch (providerError) {
        await supabase.rpc('barrio_mark_checkout_qr_uncertain', { p_user_id: req.user.sub, p_request_id: started.request_id });
        throw providerError;
      }
    }
    const { merchantId, items, deliveryMethod = 'RECOGER', deliveryAddress = null } = req.body || {};
    const key = req.get('Idempotency-Key');
    if (!id(merchantId) || !Array.isArray(items) || items.length < 1 || items.length > 50 || items.some((x) => !id(x.productId) || !Number.isInteger(x.quantity) || x.quantity < 1 || x.quantity > 100)) return res.status(422).json({ error: 'invalid_checkout' });
    if (!key || key.length < 16 || key.length > 100) return res.status(422).json({ error: 'idempotency_key_required' });
    if (!['RECOGER', 'ENTREGA_LOCAL'].includes(deliveryMethod)) return res.status(422).json({ error: 'invalid_delivery_method' });
    const created = await execute(config.db, 'app.sp_CrearPedidoPey', (r, t) => r
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('ComercioId', t.UniqueIdentifier, merchantId)
      .input('ItemsJson', t.NVarChar(sql.MAX), JSON.stringify(items))
      .input('MetodoEntrega', t.NVarChar(20), deliveryMethod)
      .input('DireccionEntrega', t.NVarChar(300), deliveryAddress)
      .input('IdempotencyKey', t.NVarChar(100), key)
      .input('ModoSimulado', t.Bit, config.paymentMode === 'simulated'));
    const payment = created.recordset?.[0];
    if (!payment) return res.status(409).json({ error: 'checkout_not_available' });
    if (config.paymentMode === 'simulated') return res.status(202).json({ orderId: payment.PedidoId, orderNumber: payment.NumeroPedido, paymentId: payment.PagoId, amountMXN: payment.Total, paymentStatus: 'PENDIENTE', simulation: true });
    if (payment.CodiStatus !== 'ACTIVE') return res.status(409).json({ error: 'merchant_bank_account_not_active', orderId: payment.PedidoId });
    const attached = await execute(config.db, 'app.sp_AdjuntarQrPey', (r, t) => r
      .input('PagoId', t.UniqueIdentifier, payment.PagoId)
      .input('UsuarioId', t.UniqueIdentifier, req.user.sub)
      .input('PeyBankAccountId', t.NVarChar(40), payment.PeyBankAccountId)
      .output('DebeCrearQr', t.Bit));
    if (!attached.output.DebeCrearQr) {
      const prior = attached.recordset?.[0];
      if (prior?.QrString) return res.status(200).json({ orderId: payment.PedidoId, paymentId: payment.PagoId, amountMXN: payment.Total, qrString: prior.QrString, qrImageDataUrl: await QRCode.toDataURL(prior.QrString), paymentStatus: 'PENDIENTE' });
      return res.status(409).json({ error: 'payment_requires_reconciliation', paymentId: payment.PagoId });
    }
    try {
      const qr = await createQr({ amount: Number(payment.Total), concept: `BARRIO ${payment.NumeroPedido}`, expiration: 600, numRef: payment.PagoReferencia, bankAccountId: payment.PeyBankAccountId, metadata: { barrioPaymentId: payment.PagoId } }, config.peyApiKey, { allowProduction: config.paymentMode === 'pey' });
      await execute(config.db, 'app.sp_GuardarQrPey', (r, t) => r
        .input('PagoId', t.UniqueIdentifier, payment.PagoId)
        .input('PeyQrId', t.NVarChar(100), qr.id)
        .input('QrString', t.NVarChar(sql.MAX), qr.qrString));
      return res.status(201).json({ orderId: payment.PedidoId, orderNumber: payment.NumeroPedido, paymentId: payment.PagoId, amountMXN: payment.Total, qrImageDataUrl: await QRCode.toDataURL(qr.qrString), paymentStatus: 'PENDIENTE' });
    } catch (providerError) {
      await execute(config.db, 'app.sp_MarcarCreacionQrIncierta', (r, t) => r.input('PagoId', t.UniqueIdentifier, payment.PagoId));
      throw providerError;
    }
  } catch (err) { next(err); }
});

app.get('/api/v1/orders/:orderId', bearer, async (req, res, next) => {
  try {
    if (supabase) {
      if (!id(req.params.orderId)) return res.status(400).json({ error: 'invalid_order_id' });
      const ownedMerchants = req.user.roles.includes('Comercio') ? await supabase.select('barrio_merchants', { select: 'id', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true' }) : [];
      const accessFilter = ownedMerchants.length ? `or=(buyer_user_id.eq.${req.user.sub},merchant_id.in.(${ownedMerchants.map((merchant) => merchant.id).join(',')}))` : `buyer_user_id=eq.${req.user.sub}`;
      const orders = await supabase.select('barrio_orders', { select: 'id,buyer_user_id,merchant_id,total_mxn,delivery_method,delivery_address,status,pey_qr_request_id,created_at,paid_at', id: `eq.${req.params.orderId}`, [accessFilter.split('=')[0]]: accessFilter.slice(accessFilter.indexOf('=')+1), limit: '1' });
      const order = orders[0];
      if (!order) return res.status(404).json({ error: 'not_found' });
      const [items, merchant, qr] = await Promise.all([
        supabase.select('barrio_order_items', { select: 'product_name,unit_price_mxn,quantity,line_total_mxn', order_id: `eq.${order.id}` }),
        supabase.select('barrio_merchants', { select: 'name,neighborhood_id', id: `eq.${order.merchant_id}`, limit: '1' }),
        order.pey_qr_request_id ? supabase.select('barrio_pey_qr_requests', { select: 'status,expires_at,paid_at', id: `eq.${order.pey_qr_request_id}`, limit: '1' }) : Promise.resolve([]),
      ]);
      if (qr[0]?.status === 'PENDING' && qr[0].expires_at && new Date(qr[0].expires_at).getTime() <= Date.now()) {
        await supabase.update('barrio_pey_qr_requests', { id: `eq.${order.pey_qr_request_id}`, status: 'eq.PENDING' }, { status: 'EXPIRED' });
        await supabase.rpc('barrio_expire_checkout_order', { p_order_id: order.id });
        qr[0].status = 'EXPIRED';
        order.status = 'EXPIRED';
      }
      return res.json({ order: { id: order.id, merchantId: order.merchant_id, merchantName: merchant[0]?.name || '', amountMXN: Number(order.total_mxn), status: order.status, paymentStatus: qr[0]?.status || order.status, deliveryMethod: order.delivery_method, deliveryAddress: order.delivery_address, items: items.map((item) => ({ name: item.product_name, price: Number(item.unit_price_mxn), quantity: item.quantity, total: Number(item.line_total_mxn) })), createdAt: order.created_at, paidAt: order.paid_at, expiresAt: qr[0]?.expires_at || null } });
    }
    if (!id(req.params.orderId)) return res.status(400).json({ error: 'invalid_order_id' });
    const result = await execute(config.db, 'app.sp_ObtenerPedidoPropio', (r, t) => r.input('UsuarioId', t.UniqueIdentifier, req.user.sub).input('PedidoId', t.UniqueIdentifier, req.params.orderId));
    const order = result.recordset?.[0];
    if (!order) return res.status(404).json({ error: 'not_found' });
    res.json({ order });
  } catch (err) { next(err); }
});

app.get('/api/v1/orders', bearer, async (req, res, next) => {
  try {
    if (supabase) {
      if (!req.user.roles.includes('Comprador')) return res.status(403).json({ error: 'forbidden' });
      const orders = await supabase.select('barrio_orders', { select: 'id,buyer_user_id,merchant_id,total_mxn,delivery_method,delivery_address,status,created_at,paid_at', buyer_user_id: `eq.${req.user.sub}`, order: 'created_at.desc', limit: '100' });
      const orderIds = orders.map((order) => order.id);
      const merchantIds = [...new Set(orders.map((order) => order.merchant_id))];
      const [merchants, items] = await Promise.all([
        merchantIds.length ? supabase.select('barrio_merchants', { select: 'id,name,neighborhood_id', id: `in.(${merchantIds.join(',')})` }) : [],
        orderIds.length ? supabase.select('barrio_order_items', { select: 'order_id,product_name,unit_price_mxn,quantity,line_total_mxn', order_id: `in.(${orderIds.join(',')})` }) : [],
      ]);
      const merchantById = new Map(merchants.map((merchant) => [merchant.id, merchant]));
      const itemsByOrder = new Map();
      for (const item of items) itemsByOrder.set(item.order_id, [...(itemsByOrder.get(item.order_id) || []), item]);
      const neighborhoods = [...new Set(merchants.map((merchant) => merchant.neighborhood_id).filter(Boolean))];
      const zones = neighborhoods.length ? await supabase.select('barrio_neighborhoods', { select: 'id,name,city', id: `in.(${neighborhoods.join(',')})` }) : [];
      const zoneById = new Map(zones.map((zone) => [zone.id, zone]));
      const statusLabels = { PENDING_PAYMENT: 'Pago pendiente', PAID: 'Nuevo', PREPARING: 'Preparando', READY: 'Listo', COMPLETED: 'Completado', CANCELLED: 'Cancelado', EXPIRED: 'Expirado' };
      return res.json({ items: orders.map((order) => {
        const merchant = merchantById.get(order.merchant_id);
        const zone = zoneById.get(merchant?.neighborhood_id);
        return { id: order.id, merchantId: order.merchant_id, merchantName: merchant?.name || 'Comercio', merchantZone: zone ? `${zone.name}, ${zone.city}` : '', amount: Number(order.total_mxn), status: statusLabels[order.status] || order.status, dbStatus: order.status, paymentStatus: order.status === 'PAID' || ['PREPARING','READY','COMPLETED'].includes(order.status) ? 'PAGADO' : order.status, deliveryMethod: order.delivery_method, createdAt: order.created_at, paidAt: order.paid_at, items: (itemsByOrder.get(order.id) || []).map((item) => ({ name: item.product_name, price: Number(item.unit_price_mxn), quantity: item.quantity, total: Number(item.line_total_mxn) })) };
      }) });
    }
    const result = await execute(config.db, 'app.sp_ListarPedidosPropios', (r, t) => r.input('UsuarioId', t.UniqueIdentifier, req.user.sub));
    res.json({ items: result.recordset || [] });
  } catch (err) { next(err); }
});

app.get('/api/v1/merchant/orders', bearer, requireRole('Comercio'), async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'merchant_orders_require_supabase_mvp' });
    const merchantId = req.query.merchantId;
    if (!id(merchantId || '')) return res.status(422).json({ error: 'merchant_id_required' });
    const owned = await supabase.select('barrio_merchants', { select: 'id', owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', id: `eq.${merchantId}`, limit: '1' });
    if (!owned[0]) return res.status(404).json({ error: 'merchant_profile_required' });
    const orders = await supabase.select('barrio_orders', { select: 'id,buyer_user_id,merchant_id,total_mxn,delivery_method,delivery_address,status,created_at,paid_at', merchant_id: `eq.${merchantId}`, order: 'created_at.desc', limit: '100' });
    const orderIds = orders.map((order) => order.id);
    const buyerIds = [...new Set(orders.map((order) => order.buyer_user_id))];
    const [profiles, items] = await Promise.all([
      buyerIds.length ? supabase.select('barrio_profiles', { select: 'user_id,display_name', user_id: `in.(${buyerIds.join(',')})` }) : [],
      orderIds.length ? supabase.select('barrio_order_items', { select: 'order_id,product_name,unit_price_mxn,quantity,line_total_mxn', order_id: `in.(${orderIds.join(',')})` }) : [],
    ]);
    const profileById = new Map(profiles.map((profile) => [profile.user_id, profile]));
    const itemsByOrder = new Map();
    for (const item of items) itemsByOrder.set(item.order_id, [...(itemsByOrder.get(item.order_id) || []), item]);
    const statusLabels = { PENDING_PAYMENT: 'Pago pendiente', PAID: 'Nuevo', PREPARING: 'Preparando', READY: 'Listo', COMPLETED: 'Completado', CANCELLED: 'Cancelado', EXPIRED: 'Expirado' };
    return res.json({ items: orders.map((order) => ({ id: order.id, merchantId: order.merchant_id, customer: profileById.get(order.buyer_user_id)?.display_name || 'Cliente', amount: Number(order.total_mxn), items: (itemsByOrder.get(order.id) || []).map((item) => ({ name: item.product_name, price: Number(item.unit_price_mxn), quantity: item.quantity, total: Number(item.line_total_mxn) })), status: statusLabels[order.status] || order.status, dbStatus: order.status, paymentStatus: order.status === 'PAID' || ['PREPARING','READY','COMPLETED'].includes(order.status) ? 'PAGADO' : order.status, deliveryMethod: order.delivery_method, deliveryAddress: order.delivery_address, createdAt: order.created_at, paidAt: order.paid_at })) });
  } catch (err) { next(err); }
});

app.patch('/api/v1/merchant/orders/:orderId/status', bearer, requireRole('Comercio'), jsonParser, async (req, res, next) => {
  try {
    if (!supabase) return res.status(501).json({ error: 'merchant_orders_require_supabase_mvp' });
    const { status } = req.body || {};
    const nextByStatus = { PAID: 'PREPARING', PREPARING: 'READY', READY: 'COMPLETED' };
    if (!id(req.params.orderId) || !['PREPARING','READY','COMPLETED'].includes(status)) return res.status(422).json({ error: 'invalid_order_status' });
    const orders = await supabase.select('barrio_orders', { select: 'id,merchant_id,status', id: `eq.${req.params.orderId}`, limit: '1' });
    const order = orders[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });
    const owned = await supabase.select('barrio_merchants', { select: 'id', id: `eq.${order.merchant_id}`, owner_user_id: `eq.${req.user.sub}`, active: 'eq.true', limit: '1' });
    if (!owned[0]) return res.status(404).json({ error: 'order_not_found' });
    if (nextByStatus[order.status] !== status) return res.status(409).json({ error: 'order_status_transition_not_allowed', currentStatus: order.status });
    const updated = await supabase.update('barrio_orders', { id: `eq.${order.id}`, merchant_id: `eq.${order.merchant_id}`, status: `eq.${order.status}` }, { status });
    if (!updated?.length) return res.status(409).json({ error: 'order_status_changed' });
    return res.json({ orderId: order.id, status });
  } catch (err) { next(err); }
});

app.post('/api/v1/webhooks/pey', express.raw({ type: 'application/json', limit: '128kb' }), async (req, res, next) => {
  try {
    const headers = { rawBody: req.body, webhookId: req.get('webhook-id'), timestamp: req.get('webhook-timestamp'), signature: req.get('webhook-signature') };
    if (!verifyPeyWebhook(headers, config.peyWebhookSecret, { toleranceSeconds: config.webhookToleranceSeconds })) return res.status(401).json({ error: 'invalid_signature' });
    let event;
    try { event = JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).json({ error: 'invalid_json' }); }
    if (!event || typeof event.type !== 'string') return res.status(400).json({ error: 'invalid_event' });
    if (supabase) {
      if (event.type !== 'codi.qr.payment_received') return res.status(202).json({ received: true, ignored: true });
      const metadataId = typeof event.metadata?.barrioQrRequestId === 'string' ? event.metadata.barrioQrRequestId : null;
      const rows = metadataId
        ? await supabase.select('barrio_pey_qr_requests', { select: 'id,merchant_id,pey_qr_id,amount_mxn,num_ref,status,transaction_id', id: `eq.${metadataId}`, limit: '1' })
        : await supabase.select('barrio_pey_qr_requests', { select: 'id,merchant_id,pey_qr_id,amount_mxn,num_ref,status,transaction_id', pey_qr_id: `eq.${event.codiQrId}`, limit: '1' });
      const qrRequest = rows[0];
      if (!qrRequest) return res.status(202).json({ received: true, ignored: true });
      const accounts = await supabase.select('barrio_pey_bank_accounts', { select: 'pey_bank_account_id', merchant_id: `eq.${qrRequest.merchant_id}`, limit: '1' });
      const accountId = accounts[0]?.pey_bank_account_id;
      if (!accountId || event.bankAccountId !== accountId || event.codiQrId !== qrRequest.pey_qr_id
        || Number(event.amount) !== Number(qrRequest.amount_mxn) || String(event.numRef) !== qrRequest.num_ref
        || typeof event.transactionId !== 'string' || !event.transactionId || !Number.isInteger(Number(event.datePaid))) {
        console.error(JSON.stringify({ event: 'pey_webhook_payment_mismatch', webhookId: headers.webhookId }));
        return res.status(422).json({ error: 'payment_details_mismatch' });
      }
      if (qrRequest.status === 'PAID' && qrRequest.transaction_id === event.transactionId) {
        // Reconcile an order if an earlier webhook updated the QR but failed before updating the order.
        await supabase.update('barrio_orders', { pey_qr_request_id: `eq.${qrRequest.id}`, status: 'in.(PENDING_PAYMENT,EXPIRED)' }, { status: 'PAID', paid_at: new Date(Number(event.datePaid) * 1000).toISOString() });
        return res.status(202).json({ received: true, duplicate: true });
      }
      const updated = await supabase.update('barrio_pey_qr_requests', { id: `eq.${qrRequest.id}`, status: 'in.(PENDING,EXPIRED)' }, {
        status: 'PAID', transaction_id: event.transactionId,
        paid_at: new Date(Number(event.datePaid) * 1000).toISOString(),
      });
      if (!updated?.length) return res.status(409).json({ error: 'payment_state_conflict' });
      await supabase.update('barrio_orders', { pey_qr_request_id: `eq.${qrRequest.id}`, status: 'in.(PENDING_PAYMENT,EXPIRED)' }, { status: 'PAID', paid_at: new Date(Number(event.datePaid) * 1000).toISOString() });
      return res.status(202).json({ received: true });
    }
    await execute(config.db, 'app.sp_ProcesarWebhookPey', (r, t) => r
      .input('WebhookId', t.NVarChar(200), headers.webhookId)
      .input('EventType', t.NVarChar(100), event.type)
      .input('PayloadJson', t.NVarChar(sql.MAX), JSON.stringify(event)));
    res.status(202).json({ received: true });
  } catch (err) { next(err); }
});

app.use((err, req, res, _next) => {
  if (err.provider === 'pey') {
    console.warn(JSON.stringify({ event: 'pey_request_rejected', path: req.path, providerStatus: err.status, providerErrorType: err.providerErrorType, providerRequestId: err.requestId }));
    return res.status(502).json({ error: 'pey_registration_rejected', providerStatus: err.status, providerErrorType: err.providerErrorType || null, providerRequestId: err.requestId || null, retryable: [400, 401, 403, 404, 409, 422, 429].includes(err.status) });
  }
  const duplicate = err.code === '23505' || [2601, 2627].includes(err.number);
  const duplicateAccount = req.path === '/api/v1/auth/register' && duplicate;
  const limitReached = String(err.message || '').includes('merchant_limit_reached');
  const publicCodes = ['bank_account_not_registered','bank_account_registration_requires_reconciliation','merchant_bank_account_not_active','merchant_profile_required','merchant_limit_reached','idempotency_key_conflict','active_qr_exists','qr_request_requires_reconciliation','buyer_role_required','merchant_codi_not_enabled','merchant_not_available','product_not_available','insufficient_stock','delivery_address_required','order_not_found','order_already_paid','checkout_requires_reconciliation'];
  const publicCode = publicCodes.find((code) => String(err.message || '').includes(code));
  // PostgREST reports PL/pgSQL business exceptions (SQLSTATE 55000) as HTTP
  // 500. Preserve the domain conflict so clients can explain active QR and
  // account-state conflicts instead of showing a misleading internal_error.
  const domainConflict = err.code === '55000' && [
    'merchant_bank_account_not_active', 'merchant_codi_not_enabled', 'active_qr_exists',
    'order_already_paid', 'checkout_requires_reconciliation',
  ].includes(publicCode);
  const status = duplicateAccount || limitReached || domainConflict ? 409 : (err.status || (err instanceof TypeError ? 422 : ([2601, 2627, 50102, 50104, 50108, 50109, 50111].includes(err.number) ? 409 : ([50101, 50103, 50105].includes(err.number) ? 403 : ([50112, 50114, 50119, 50122].includes(err.number) ? 409 : 500)))));
  if (status >= 500) console.error(JSON.stringify({
    event: 'api_error', method: req.method, path: req.path, status,
    name: err.name, code: err.code || err.number || null,
    message: err.message, provider: err.provider || null,
    providerStatus: err.status || null, providerErrorType: err.providerErrorType || null,
    requestId: err.requestId || null,
  }));
  res.status(status).json({ error: status >= 500 ? 'internal_error' : (duplicateAccount ? 'account_contact_already_registered' : publicCode || 'request_failed'), ...(err.requestId ? { providerRequestId: err.requestId } : {}) });
});

export default app;

if (process.env.VERCEL !== '1') {
  const server = app.listen(config.port, '0.0.0.0', () => console.log(`BARRIO API listening on ${config.port}; database=${config.databaseProvider}; payments=${config.paymentMode}`));
  const reservationSweep = config.databaseProvider === 'sqlserver' ? setInterval(() => {
    execute(config.db, 'app.sp_LiberarReservasPeyVencidas').catch((err) => console.error(JSON.stringify({ event: 'reservation_sweep_failed', name: err.name })));
  }, 60_000) : null;
  reservationSweep?.unref();
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
    if (reservationSweep) clearInterval(reservationSweep);
    server.close(); if (config.databaseProvider === 'sqlserver') await closePool(); process.exit(0);
  });
}
