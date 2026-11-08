let poolPromise;
// Keep SQL Server optional at runtime: the Supabase deployment must not load
// the Azure/MSSQL driver unless a SQL Server connection is actually requested.
export let sql = { MAX: -1 };

async function configFor(config) {
  const base = {
    server: config.server,
    database: config.database,
    options: { encrypt: true, trustServerCertificate: config.trustServerCertificate ?? false, enableArithAbort: true },
    pool: { min: 0, max: 10, idleTimeoutMillis: 30000 },
    connectionTimeout: 15000,
    requestTimeout: 30000,
  };
  if (config.authMode === 'sql-password') {
    if (!config.user || !config.password) throw new Error('SQL password mode requires BARRIO_DB_USER and BARRIO_DB_PASSWORD');
    return { ...base, user: config.user, password: config.password };
  }
  return {
    ...base,
    authentication: { type: 'azure-active-directory-default', options: config.clientId ? { clientId: config.clientId } : {} },
  };
}

export async function getPool(config) {
  if (!poolPromise) {
    poolPromise = import('mssql').then(async (driver) => {
      sql = driver.default;
      const c = await configFor(config);
      return new sql.ConnectionPool(c).connect();
    }).catch((e) => {
      poolPromise = undefined;
      throw e;
    });
  }
  return poolPromise;
}

export async function execute(config, procedure, bind) {
  const pool = await getPool(config);
  const request = pool.request();
  bind?.(request, sql);
  return request.execute(procedure);
}

export async function query(config, statement, bind) {
  const pool = await getPool(config);
  const request = pool.request();
  bind?.(request, sql);
  return request.query(statement);
}

export async function closePool() {
  if (poolPromise) (await poolPromise).close();
  poolPromise = undefined;
}
