# BARRIO — demo de interfaz

Prototipo frontend navegable para una red social de comerciantes. Incluye pantallas de inicio, mapa ilustrado, perfil de negocio, mensajes/chat local, publicación y perfil personal. Todo el contenido y estado son de ejemplo; no hay servidor, cuenta, API ni persistencia.

## Cómo abrir

Abre `index.html` directamente en un navegador moderno. No requiere instalación ni configuración. En computadora se muestra dentro de un marco de teléfono; en pantalla móvil ocupa el viewport.

## Interacciones incluidas

- Navegación inferior entre las cinco secciones principales.
- Búsqueda local de comercios, publicaciones y conversaciones.
- Filtros y marcadores seleccionables en el mapa ilustrado.
- Acceso al perfil de un comercio, botón Conectar y acceso al chat.
- Chat y publicación simulados en memoria durante la sesión.
- Selección local del tipo de publicación, herramientas visuales y audiencia.
- Flujo guiado de marketing desde Perfil > Impulsa tu negocio: objetivo, producto, audiencia y revisión; permite guardar un borrador temporal o publicar una propuesta de ejemplo en Inicio.
- Primeros pasos con selección de rol, perfiles de cliente/comercio, intereses, métodos de pago locales (incluido NFC) y wallet opcional.
- Compra de ejemplo de productos de Café Nopal: catálogo, carrito, entrega, pago simulado y confirmación.
- Checkout agrupado por tipo de pago: tarjeta y wallets, banco (incluido CoDi QR con Pey), pago en comercio y cripto.
- Registro de CLABE con autorización explícita y consulta de estado de Pey, siempre que las credenciales privadas del servidor estén configuradas.
- Cobro presencial CoDi con importe y concepto manuales, QR real de Pey y confirmación de pago por webhook firmado. Requiere la migración de Supabase y la activación de producción; el carrito y checkout general siguen siendo demostrativos.
- Herramientas del comerciante: panel, inventario editable, pedidos y estados, ventas, clientes y tienda pública.
