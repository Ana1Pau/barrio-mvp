# BARRIO MVP

MVP de BARRIO: una plataforma para descubrir comercios locales, administrar negocios y productos, y probar pedidos y cobros CoDi mediante Pey. Incluye una landing, una app web, una API y migraciones para Supabase.

## Estructura

- `apps/landing/`: landing de presentación.
- `apps/prototype/`: interfaz principal de cliente y comerciante.
- `apps/api/`: API Express para cuentas, negocios, productos, pedidos y Pey.
- `apps/barrio-2/`: mapa y directorio de tianguis.
- `public/`: archivos servidos por Vercel, incluida la app en `/app` y el mapa en `/map`.
- `supabase/migrations/`: migraciones de base de datos en orden cronológico.
- `database/`: esquema SQL Server heredado, ejemplos de conexión y guías.
- `docs/`: guía de activación de Pey, manual visual y documento de coordinación del MVP con auditoría UX.

## Desarrollo local

Requisitos: Node.js 20 o superior y un proyecto Supabase. Instala las dependencias desde la raíz:

```sh
npm ci
```

Copia `apps/api/.env.example` a `apps/api/.env` y completa localmente las variables necesarias. No agregues archivos `.env` con valores reales al repositorio. Para iniciar la API:

```sh
npm run dev --workspace apps/api
```

Sirve `public/` con un servidor estático local para probar la interfaz. La app usa la API en `/api/v1`.

## Base de datos

Aplica los archivos de `supabase/migrations/` en orden (`20261108000100` a `20261108000400`) desde Supabase SQL Editor. Revisa [`supabase/README.md`](supabase/README.md) y [`database/README.md`](database/README.md) antes de configurar otra instancia.

## Pey y datos sensibles

La integración registra cuentas CoDi, consulta su estado y solicita QR cuando una cuenta está activa. Pey recibe los datos bancarios del titular durante el registro; BARRIO solo conserva la referencia de Pey, el estado y los últimos cuatro dígitos de la CLABE. El QR real puede producir pagos reales: no uses cuentas o datos de terceros sin autorización.

Configura `PEY_API_KEY`, `PEY_WEBHOOK_SECRET` y las variables de Supabase únicamente en el entorno del servidor (por ejemplo, Vercel Environment Variables). Nunca las pongas en archivos del frontend, commits, capturas o mensajes. Consulta [`docs/pey-codi-activacion.md`](docs/pey-codi-activacion.md) antes de habilitar Pey.

## Estado del MVP

El producto está en desarrollo y la integración de Pey funciona contra su API de producción; Pey no ofrece un entorno dedicado de pruebas en su documentación actual. Las altas CoDi y los cobros dependen de los permisos, validaciones y estados que devuelve Pey y Banxico. Consulta el tablero y el [documento de coordinación del MVP y auditoría UX](docs/BARRIO-KYRA_coordinacion-y-auditoria-UX.pdf) para distinguir flujos listos, pendientes y demostrativos, y alinear la revisión entre socios.

