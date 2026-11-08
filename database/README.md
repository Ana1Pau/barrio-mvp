# Base de datos de Barrio MVP

Barrio MVP conserva SQL Server y sus scripts base de BARRIO. Las migraciones `sql/13_api_runtime.sql`, `sql/14_onboarding.sql` y `sql/15_directory_and_pey_status.sql` añaden la API persistente, el registro de perfil y negocio, los métodos de cobro con su estado de configuración, la visibilidad pública del comercio y la sincronización del estado CoDi con Pey.

## Desarrollo local

1. Copia `database/docker/.env.example` como `database/docker/.env` y reemplaza los tres secretos locales. No pongas la API key de Pey en el repositorio ni en el chat.
2. Desde `database/docker`, levanta la base y la API con Docker Compose. SQL queda en `localhost:1434` y la API/interfaz en `http://localhost:8081`.
3. El inicio crea `BarrioDB`, aplica los scripts base si hace falta, ejecuta las migraciones 13, 14 y 15, y crea un usuario SQL de mínimo privilegio para la API.

La configuración inicial `PAYMENTS_MODE=simulated` deja los cobros reales desactivados. El alta del perfil personal, del negocio y de las preferencias de cobro desde onboarding sí se envía a la API y se guarda en SQL. Efectivo queda disponible; CoDi con Pey se registra como pendiente de configuración; tarjeta, SPEI, wallets y NFC no se anuncian como activos. Las pantallas de catálogo, checkout y pedidos siguen siendo de demostración y todavía no crean pedidos desde la interfaz.

## Pey

El runtime ya incluye la ruta técnica para alta/verificación de cuenta del comercio, creación de QR CoDi y recepción de webhook firmado. Para usar esos endpoints debe existir una API key válida y un secreto webhook en la configuración local, y la cuenta bancaria del comercio debe ser aprobada por Pey. No habilites cargos reales hasta completar la revisión del flujo, la configuración de webhook y la decisión explícita de pasar a producción.

En este MVP no se guarda la CLABE completa ni la API key en la base. La CLABE se envía a Pey durante el alta y solo se conserva su terminación; la API key y el secreto webhook son variables de entorno del servidor.

## Nota sobre el esquema previo

Los scripts heredados incluyen conceptos HBAR y pagos genéricos. La ruta prioritaria del MVP es CoDi de Pey con liquidación directa al comercio; el esquema legado no implica una integración HBAR activa.
