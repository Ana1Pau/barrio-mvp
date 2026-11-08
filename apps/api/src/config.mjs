const required = (name, value) => {
  if (!value) throw new Error(`${name} is required`);
  return value;
};

export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const databaseProvider = env.BARRIO_DATABASE_PROVIDER || (nodeEnv === 'production' ? 'supabase' : 'sqlserver');
  if (!['sqlserver', 'supabase'].includes(databaseProvider)) throw new Error('BARRIO_DATABASE_PROVIDER must be sqlserver or supabase');
  const authMode = env.BARRIO_DB_AUTH_MODE || (nodeEnv === 'production' ? 'azure-managed-identity' : 'sql-password');
  const paymentMode = env.PAYMENTS_MODE || 'simulated';
  const liveChargesEnabled = env.PEY_LIVE_CHARGES_ENABLED === 'true';
  if (!['sql-password', 'azure-managed-identity'].includes(authMode)) throw new Error('Unsupported BARRIO_DB_AUTH_MODE');
  if (!['simulated', 'pey'].includes(paymentMode)) throw new Error('PAYMENTS_MODE must be simulated or pey');
  if (databaseProvider === 'sqlserver' && nodeEnv === 'production' && authMode === 'sql-password' && env.BARRIO_ALLOW_SQL_PASSWORD_AUTH !== 'true') throw new Error('Production requires managed identity for SQL unless the explicit local-container override is enabled');
  if (nodeEnv === 'production' && paymentMode === 'simulated') {
    // Simulation is deliberately allowed in production deployments until owners enable live payments.
  }
  const jwtSecret = required('JWT_SECRET', env.JWT_SECRET);
  if (Buffer.byteLength(jwtSecret) < 32) throw new Error('JWT_SECRET must contain at least 32 bytes');
  if (paymentMode === 'pey') {
    if (nodeEnv !== 'production' || !liveChargesEnabled) throw new Error('Live Pey requests require production and PEY_LIVE_CHARGES_ENABLED=true');
    required('PEY_API_KEY', env.PEY_API_KEY);
    required('PEY_WEBHOOK_SECRET', env.PEY_WEBHOOK_SECRET);
  }
  return {
    nodeEnv,
    databaseProvider,
    port: Number(env.PORT || 8080),
    corsOrigins: (env.CORS_ORIGINS || 'http://localhost:4176').split(',').map((x) => x.trim()).filter(Boolean),
    jwtSecret,
    db: databaseProvider === 'sqlserver' ? {
      server: required('BARRIO_DB_SERVER', env.BARRIO_DB_SERVER),
      database: required('BARRIO_DB_NAME', env.BARRIO_DB_NAME),
      authMode,
      trustServerCertificate: env.BARRIO_DB_TRUST_SERVER_CERTIFICATE === 'true',
      clientId: env.AZURE_CLIENT_ID,
      user: env.BARRIO_DB_USER,
      password: env.BARRIO_DB_PASSWORD,
    } : null,
    supabase: databaseProvider === 'supabase' ? {
      url: required('SUPABASE_URL', env.SUPABASE_URL),
      secretKey: required('SUPABASE_SECRET_KEY or SUPABASE_SERVICE_ROLE_KEY', env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY),
    } : null,
    paymentMode,
    peyApiKey: env.PEY_API_KEY,
    peyWebhookSecret: env.PEY_WEBHOOK_SECRET,
    webhookToleranceSeconds: Number(env.PEY_WEBHOOK_TOLERANCE_SECONDS || 300),
  };
}
