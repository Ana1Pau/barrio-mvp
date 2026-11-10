# Activar cobros CoDi con Pey

## Alcance de esta primera conexión

El comercio registra su propia CLABE en **Más → Cobros y cuenta Pey**. BARRIO envía la CLABE y los datos del titular directamente a Pey con autorización explícita; BARRIO solo guarda el identificador que devuelve Pey, los últimos cuatro dígitos y el estado.

Cuando Pey marque la cuenta como `ACTIVE`, el comercio puede crear una solicitud CoDi presencial indicando importe y concepto. El QR vence a los diez minutos. El dinero solo se mueve si la persona que paga confirma la operación en su banco. Un webhook firmado de Pey marca el registro como pagado.

Esta entrega no vuelve reales el catálogo, carrito ni checkout general: esos siguen con datos de demostración. El QR real se genera desde las herramientas del comercio y no se debe presentar como pago de un pedido de la tienda.

## Pasos antes de habilitarlo

1. En Supabase → **SQL Editor**, ejecutar en orden las migraciones `supabase/migrations/20261108000100_barrio_onboarding.sql` y `supabase/migrations/20261108000200_barrio_pey_qr_cobros.sql`.
2. En el portal de Pey, crear una API key de producción y configurar el webhook `https://barrio-mvp.vercel.app/api/v1/webhooks/pey` para el evento de pago de QR CoDi (`codi.qr.payment_received`). Guardar el secreto de firma que Pey muestra al crear el webhook.
3. En Vercel → proyecto **barrio-mvp** → Settings → Environment Variables, agregar `PEY_API_KEY` y `PEY_WEBHOOK_SECRET` para Production. No ponerlos en `apps/prototype`, en variables `NEXT_PUBLIC_*`, ni en el navegador.
4. Cambiar `PAYMENTS_MODE` a `pey` y `PEY_LIVE_CHARGES_ENABLED` a `true` en Production. Redeplegar.
5. Abrir **Más → Cobros y cuenta Pey**, capturar la CLABE real del comercio y los datos del titular, marcar la autorización y registrar. El estado se consulta en Pey; el QR solo aparece cuando sea `ACTIVE`.
6. Generar un QR con un importe pequeño y confirmar en pantalla que el nombre del beneficiario, cuenta e importe sean correctos antes de pagar desde una app bancaria. El pago es real y no se revierte automáticamente.

## Diagnóstico de rechazos al registrar la cuenta

En una revisión de cinco intentos, Pey devolvió `HTTP 400 · INCOMPLETE_PARAMETERS` para todos. La causa común identificada en el adaptador era que el alias se enviaba solo si el usuario lo capturaba, aunque el contrato de Pey lo requiere siempre. Además, BARRIO enviaba `entity` como `person` o `business`; Pey espera `PERSON` o `BUSINESS`.

El adaptador ahora completa el alias con el nombre del titular cuando se deja vacío y normaliza `entity` a mayúsculas antes de llamar a `POST /bank-account`. Esta corrección está en el código local; no se debe volver a intentar el registro desde producción hasta que el cambio esté publicado. Para revisar un próximo rechazo, conserva el `requestId` de Pey y consulta su mensaje de error sin compartir la CLABE ni la API key.

Pey indica que la activación CoDi de una cuenta puede tardar hasta cinco días hábiles. La API de QR exige una cuenta `ACTIVE`, acepta importes en MXN y permite un vencimiento mínimo de seis minutos. BARRIO usa diez minutos. Ver [requisitos iniciales de Pey](https://docs.pey.mx/docs/tutorials/getting-started/create-an-api-key/), [crear QR](https://docs.pey.mx/docs/api/create-qr/) y [webhook de pago QR](https://docs.pey.mx/docs/webhooks/codi/qr/).

## Seguridad y operación

- Nunca pedir o pegar la API key ni el secreto de firma en el chat.
- Nunca guardar la CLABE completa, API key, secreto de webhook o datos bancarios completos en la base de BARRIO.
- No volver a enviar un registro o crear un QR si la interfaz informa que el resultado quedó incierto; primero reconciliarlo con Pey para evitar duplicados.
- El estado pagado se marca exclusivamente después de validar la firma del webhook y comparar cuenta, QR, importe, referencia y transacción.
- Una cuenta `PENDING` o `ERROR` no puede generar solicitudes de pago.
