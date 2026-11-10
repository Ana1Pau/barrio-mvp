-- Merchant-owned catalog and CoDi checkout for the Supabase-backed MVP.
-- Pey creates the QR; the customer still authorizes every payment in their bank.

create table if not exists public.barrio_products (
  id uuid primary key default gen_random_uuid(),
  merchant_id uuid not null references public.barrio_merchants(id) on delete cascade,
  name text not null check (length(trim(name)) between 1 and 150),
  description text check (description is null or length(description) <= 160),
  category text not null default 'Otros',
  price_mxn numeric(10,2) not null check (price_mxn > 0),
  stock integer not null default 0 check (stock >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists barrio_products_public_by_merchant
  on public.barrio_products(merchant_id, active, name);

create table if not exists public.barrio_orders (
  id uuid primary key default gen_random_uuid(),
  buyer_user_id uuid not null references public.barrio_users(id),
  merchant_id uuid not null references public.barrio_merchants(id),
  idempotency_key text not null,
  total_mxn numeric(10,2) not null check (total_mxn > 0),
  delivery_method text not null check (delivery_method in ('RECOGER','ENTREGA_LOCAL')),
  delivery_address text,
  status text not null default 'PENDING_PAYMENT'
    check (status in ('PENDING_PAYMENT','PAID','PREPARING','READY','COMPLETED','CANCELLED','EXPIRED')),
  pey_qr_request_id uuid references public.barrio_pey_qr_requests(id),
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  unique (buyer_user_id, idempotency_key)
);
create index if not exists barrio_orders_merchant_recent
  on public.barrio_orders(merchant_id, created_at desc);
create index if not exists barrio_orders_buyer_recent
  on public.barrio_orders(buyer_user_id, created_at desc);

create table if not exists public.barrio_order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.barrio_orders(id) on delete cascade,
  product_id uuid not null references public.barrio_products(id),
  product_name text not null,
  unit_price_mxn numeric(10,2) not null check (unit_price_mxn > 0),
  quantity integer not null check (quantity between 1 and 100),
  line_total_mxn numeric(10,2) not null check (line_total_mxn > 0)
);

alter table public.barrio_products enable row level security;
alter table public.barrio_orders enable row level security;
alter table public.barrio_order_items enable row level security;
revoke all on public.barrio_products, public.barrio_orders, public.barrio_order_items from anon, authenticated;
grant select, insert, update on public.barrio_products to service_role;
grant select, insert, update on public.barrio_orders to service_role;
grant select, insert on public.barrio_order_items to service_role;

create or replace function public.barrio_create_checkout_order(
  p_user_id uuid, p_merchant_id uuid, p_key text, p_items jsonb,
  p_delivery_method text, p_delivery_address text default null
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_order public.barrio_orders%rowtype;
  v_item jsonb;
  v_product public.barrio_products%rowtype;
  v_quantity integer;
  v_total numeric(10,2) := 0;
  v_order_id uuid;
begin
  if p_key is null or length(p_key)<16 or length(p_key)>100 then raise exception 'idempotency_key_required' using errcode='22023'; end if;
  if p_delivery_method not in ('RECOGER','ENTREGA_LOCAL') then raise exception 'invalid_delivery_method' using errcode='22023'; end if;
  if p_delivery_method='ENTREGA_LOCAL' and coalesce(length(trim(p_delivery_address)),0)=0 then raise exception 'delivery_address_required' using errcode='22023'; end if;
  if jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)<1 or jsonb_array_length(p_items)>50 then raise exception 'invalid_checkout' using errcode='22023'; end if;
  if not exists(select 1 from public.barrio_users where id=p_user_id and active and 'Comprador'=any(roles)) then raise exception 'buyer_role_required' using errcode='42501'; end if;
  if not exists(select 1 from public.barrio_merchants where id=p_merchant_id and active) then raise exception 'merchant_not_available' using errcode='P0002'; end if;
  if not exists(select 1 from public.barrio_pey_bank_accounts where merchant_id=p_merchant_id and codi_status='ACTIVE') then raise exception 'merchant_bank_account_not_active' using errcode='55000'; end if;
  if not exists(select 1 from public.barrio_merchant_payment_methods where merchant_id=p_merchant_id and method_code='PEY_CODI' and selected and enabled) then raise exception 'merchant_codi_not_enabled' using errcode='55000'; end if;

  select * into v_order from public.barrio_orders where buyer_user_id=p_user_id and idempotency_key=p_key;
  if found then
    if v_order.merchant_id<>p_merchant_id then raise exception 'idempotency_key_conflict' using errcode='23505'; end if;
    return jsonb_build_object('order_id',v_order.id,'merchant_id',v_order.merchant_id,'total_mxn',v_order.total_mxn,'status',v_order.status,'pey_qr_request_id',v_order.pey_qr_request_id,'created_at',v_order.created_at);
  end if;

  v_order_id := gen_random_uuid();
  for v_item in select value from jsonb_array_elements(p_items) loop
    if not (v_item ? 'productId') or not (v_item ? 'quantity') then raise exception 'invalid_checkout_item' using errcode='22023'; end if;
    v_quantity := (v_item->>'quantity')::integer;
    if v_quantity<1 or v_quantity>100 then raise exception 'invalid_checkout_item' using errcode='22023'; end if;
    select * into v_product from public.barrio_products
      where id=(v_item->>'productId')::uuid and merchant_id=p_merchant_id and active for update;
    if not found then raise exception 'product_not_available' using errcode='P0002'; end if;
    if v_product.stock<v_quantity then raise exception 'insufficient_stock' using errcode='P0001'; end if;
    update public.barrio_products set stock=stock-v_quantity,updated_at=now() where id=v_product.id;
    v_total := v_total + v_product.price_mxn*v_quantity;
  end loop;
  if v_total<=0 or v_total>1000000 then raise exception 'invalid_order_total' using errcode='22023'; end if;
  insert into public.barrio_orders(id,buyer_user_id,merchant_id,idempotency_key,total_mxn,delivery_method,delivery_address)
    values(v_order_id,p_user_id,p_merchant_id,p_key,v_total,p_delivery_method,nullif(trim(p_delivery_address),'')) returning * into v_order;
  for v_item in select value from jsonb_array_elements(p_items) loop
    v_quantity := (v_item->>'quantity')::integer;
    select * into v_product from public.barrio_products where id=(v_item->>'productId')::uuid and merchant_id=p_merchant_id;
    insert into public.barrio_order_items(order_id,product_id,product_name,unit_price_mxn,quantity,line_total_mxn)
      values(v_order_id,v_product.id,v_product.name,v_product.price_mxn,v_quantity,v_product.price_mxn*v_quantity);
  end loop;
  return jsonb_build_object('order_id',v_order.id,'merchant_id',v_order.merchant_id,'total_mxn',v_order.total_mxn,'status',v_order.status,'created_at',v_order.created_at);
end $$;

create or replace function public.barrio_expire_checkout_order(p_order_id uuid)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
declare v_order_id uuid;
begin
  with expired as (
    update public.barrio_orders o set status='EXPIRED'
    where o.id=p_order_id and o.status='PENDING_PAYMENT'
      and exists(select 1 from public.barrio_pey_qr_requests q where q.id=o.pey_qr_request_id and q.status='EXPIRED' and q.expires_at<=now())
    returning o.id
  )
  select id into v_order_id from expired;
  if v_order_id is not null then
    update public.barrio_products p set stock=p.stock+oi.quantity,updated_at=now()
    from public.barrio_order_items oi where oi.order_id=v_order_id and p.id=oi.product_id;
  end if;
end $$;

create or replace function public.barrio_begin_checkout_qr(p_user_id uuid,p_order_id uuid,p_key text,p_num_ref text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_order public.barrio_orders%rowtype; v_bank public.barrio_pey_bank_accounts%rowtype; v_existing public.barrio_pey_qr_requests%rowtype; v_request public.barrio_pey_qr_requests%rowtype;
begin
  select * into v_order from public.barrio_orders where id=p_order_id and buyer_user_id=p_user_id for update;
  if not found then raise exception 'order_not_found' using errcode='P0002'; end if;
  if v_order.status='PAID' then raise exception 'order_already_paid' using errcode='55000'; end if;
  if v_order.pey_qr_request_id is not null then
    select * into v_existing from public.barrio_pey_qr_requests where id=v_order.pey_qr_request_id;
    if v_existing.status='PENDING' and v_existing.expires_at<=now() then
      update public.barrio_pey_qr_requests set status='EXPIRED' where id=v_existing.id;
      v_existing.status := 'EXPIRED';
    end if;
    if v_existing.status='EXPIRED' then perform public.barrio_expire_checkout_order(v_order.id); end if;
    return jsonb_build_object('should_create',false,'request_id',v_existing.id,'status',v_existing.status,'pey_qr_id',v_existing.pey_qr_id,'qr_string',v_existing.qr_string,'amount_mxn',v_existing.amount_mxn,'concept',v_existing.concept,'num_ref',v_existing.num_ref,'created_at',v_existing.created_at,'expires_at',v_existing.expires_at,'bank_account_id',null);
  end if;
  select * into v_bank from public.barrio_pey_bank_accounts where merchant_id=v_order.merchant_id and codi_status='ACTIVE';
  if not found then raise exception 'merchant_bank_account_not_active' using errcode='55000'; end if;
  update public.barrio_pey_qr_requests set status='EXPIRED' where merchant_id=v_order.merchant_id and status='PENDING' and expires_at<=now();
  for v_existing in select q.* from public.barrio_pey_qr_requests q join public.barrio_orders o on o.pey_qr_request_id=q.id where q.merchant_id=v_order.merchant_id and q.status='EXPIRED' and o.status='PENDING_PAYMENT' loop
    perform public.barrio_expire_checkout_order((select o.id from public.barrio_orders o where o.pey_qr_request_id=v_existing.id limit 1));
  end loop;
  if exists(select 1 from public.barrio_pey_qr_requests where merchant_id=v_order.merchant_id and status in ('CREATING','PENDING','UNCERTAIN')) then raise exception 'active_qr_exists' using errcode='55000'; end if;
  insert into public.barrio_pey_qr_requests(merchant_id,idempotency_key,amount_mxn,concept,num_ref,status)
    values(v_order.merchant_id,p_key,v_order.total_mxn,'Pedido BARRIO',p_num_ref,'CREATING') returning * into v_request;
  update public.barrio_orders set pey_qr_request_id=v_request.id where id=v_order.id;
  return jsonb_build_object('should_create',true,'request_id',v_request.id,'merchant_id',v_order.merchant_id,'bank_account_id',v_bank.pey_bank_account_id,'status',v_request.status,'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref);
end $$;

create or replace function public.barrio_finish_checkout_qr(p_user_id uuid,p_request_id uuid,p_pey_qr_id text,p_qr_string text,p_expires_at timestamptz)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_order public.barrio_orders%rowtype; v_request public.barrio_pey_qr_requests%rowtype;
begin
  select o.* into v_order from public.barrio_orders o join public.barrio_pey_qr_requests q on q.id=o.pey_qr_request_id where q.id=p_request_id and o.buyer_user_id=p_user_id for update of o;
  if not found then raise exception 'order_not_found' using errcode='P0002'; end if;
  update public.barrio_pey_qr_requests set pey_qr_id=p_pey_qr_id,qr_string=p_qr_string,status='PENDING',expires_at=p_expires_at where id=p_request_id and status='CREATING' returning * into v_request;
  if not found then raise exception 'qr_request_not_found' using errcode='P0002'; end if;
  return jsonb_build_object('id',v_request.id,'pey_qr_id',v_request.pey_qr_id,'qr_string',v_request.qr_string,'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref,'status',v_request.status,'created_at',v_request.created_at,'expires_at',v_request.expires_at);
end $$;

create or replace function public.barrio_mark_checkout_qr_uncertain(p_user_id uuid,p_request_id uuid)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  update public.barrio_pey_qr_requests q set status='UNCERTAIN' from public.barrio_orders o
  where q.id=p_request_id and o.pey_qr_request_id=q.id and o.buyer_user_id=p_user_id and q.status='CREATING';
end $$;

revoke all on function public.barrio_create_checkout_order(uuid,uuid,text,jsonb,text,text) from public,anon,authenticated;
revoke all on function public.barrio_begin_checkout_qr(uuid,uuid,text,text) from public,anon,authenticated;
revoke all on function public.barrio_finish_checkout_qr(uuid,uuid,text,text,timestamptz) from public,anon,authenticated;
revoke all on function public.barrio_mark_checkout_qr_uncertain(uuid,uuid) from public,anon,authenticated;
revoke all on function public.barrio_expire_checkout_order(uuid) from public,anon,authenticated;
grant execute on function public.barrio_create_checkout_order(uuid,uuid,text,jsonb,text,text) to service_role;
grant execute on function public.barrio_begin_checkout_qr(uuid,uuid,text,text) to service_role;
grant execute on function public.barrio_finish_checkout_qr(uuid,uuid,text,text,timestamptz) to service_role;
grant execute on function public.barrio_mark_checkout_qr_uncertain(uuid,uuid) to service_role;
grant execute on function public.barrio_expire_checkout_order(uuid) to service_role;
