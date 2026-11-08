-- Durable CoDi QR collection requests for merchant initiated in person charges.
create table if not exists public.barrio_pey_qr_requests (
  id uuid primary key default gen_random_uuid(),
  merchant_id uuid not null references public.barrio_merchants(id) on delete cascade,
  idempotency_key text not null,
  amount_mxn numeric(10,2) not null check (amount_mxn > 0 and amount_mxn <= 1000000),
  concept text not null check (length(trim(concept)) between 1 and 100),
  num_ref varchar(7) not null check (num_ref ~ '^[0-9]{1,7}$'),
  pey_qr_id text unique,
  qr_string text,
  status text not null check (status in ('CREATING','PENDING','PAID','UNCERTAIN','EXPIRED')),
  transaction_id text unique,
  paid_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  unique (merchant_id, idempotency_key)
);
create unique index if not exists barrio_pey_qr_one_open_request_per_merchant
  on public.barrio_pey_qr_requests(merchant_id)
  where status in ('CREATING','PENDING','UNCERTAIN');

alter table public.barrio_pey_qr_requests enable row level security;
revoke all on public.barrio_pey_qr_requests from anon, authenticated;
grant select, insert, update on public.barrio_pey_qr_requests to service_role;

create or replace function public.barrio_begin_pey_qr(
  p_user_id uuid, p_key text, p_amount numeric, p_concept text, p_num_ref text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_merchant_id uuid;
  v_bank public.barrio_pey_bank_accounts%rowtype;
  v_existing public.barrio_pey_qr_requests%rowtype;
  v_request public.barrio_pey_qr_requests%rowtype;
begin
  if p_key is null or length(p_key) < 16 or length(p_key) > 100 then raise exception 'idempotency_key_required' using errcode='22023'; end if;
  if p_amount is null or p_amount <= 0 or p_amount > 1000000 then raise exception 'invalid_amount' using errcode='22023'; end if;
  if p_concept is null or length(trim(p_concept)) < 1 or length(p_concept) > 100 then raise exception 'invalid_concept' using errcode='22023'; end if;
  if p_num_ref is null or p_num_ref !~ '^[0-9]{1,7}$' then raise exception 'invalid_reference' using errcode='22023'; end if;

  select id into v_merchant_id from public.barrio_merchants
    where owner_user_id=p_user_id and active for update;
  if v_merchant_id is null then raise exception 'merchant_profile_required' using errcode='23503'; end if;
  select * into v_bank from public.barrio_pey_bank_accounts where merchant_id=v_merchant_id;
  if not found then raise exception 'bank_account_not_registered' using errcode='23503'; end if;
  if v_bank.codi_status <> 'ACTIVE' then raise exception 'merchant_bank_account_not_active' using errcode='55000'; end if;

  select * into v_existing from public.barrio_pey_qr_requests
    where merchant_id=v_merchant_id and idempotency_key=p_key;
  if found then
    if v_existing.amount_mxn <> p_amount or v_existing.concept <> trim(p_concept) then
      raise exception 'idempotency_key_conflict' using errcode='23505';
    end if;
    return jsonb_build_object('should_create',false,'request_id',v_existing.id,'status',v_existing.status,
      'pey_qr_id',v_existing.pey_qr_id,'qr_string',v_existing.qr_string,'amount_mxn',v_existing.amount_mxn,
      'concept',v_existing.concept,'num_ref',v_existing.num_ref,'created_at',v_existing.created_at,'expires_at',v_existing.expires_at);
  end if;

  update public.barrio_pey_qr_requests set status='EXPIRED'
    where merchant_id=v_merchant_id and status='PENDING' and expires_at <= now();
  if exists (select 1 from public.barrio_pey_qr_requests
    where merchant_id=v_merchant_id and status in ('CREATING','PENDING','UNCERTAIN')) then
    raise exception 'active_qr_exists' using errcode='55000';
  end if;

  insert into public.barrio_pey_qr_requests(merchant_id,idempotency_key,amount_mxn,concept,num_ref,status)
    values(v_merchant_id,p_key,p_amount,trim(p_concept),p_num_ref,'CREATING') returning * into v_request;
  return jsonb_build_object('should_create',true,'request_id',v_request.id,'merchant_id',v_merchant_id,
    'bank_account_id',v_bank.pey_bank_account_id,'status',v_request.status,'amount_mxn',v_request.amount_mxn,
    'concept',v_request.concept,'num_ref',v_request.num_ref);
end $$;

create or replace function public.barrio_finish_pey_qr(
  p_user_id uuid,p_request_id uuid,p_pey_qr_id text,p_qr_string text,p_expires_at timestamptz
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_request public.barrio_pey_qr_requests%rowtype;
begin
  update public.barrio_pey_qr_requests q set pey_qr_id=p_pey_qr_id,qr_string=p_qr_string,
    status='PENDING',expires_at=p_expires_at
  from public.barrio_merchants m
  where q.id=p_request_id and q.merchant_id=m.id and m.owner_user_id=p_user_id
    and q.status='CREATING'
  returning q.* into v_request;
  if not found then raise exception 'qr_request_not_found' using errcode='P0002'; end if;
  return jsonb_build_object('id',v_request.id,'pey_qr_id',v_request.pey_qr_id,'qr_string',v_request.qr_string,
    'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref,
    'status',v_request.status,'created_at',v_request.created_at,'expires_at',v_request.expires_at);
end $$;

create or replace function public.barrio_mark_pey_qr_uncertain(p_user_id uuid,p_request_id uuid)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  update public.barrio_pey_qr_requests q set status='UNCERTAIN'
  from public.barrio_merchants m
  where q.id=p_request_id and q.merchant_id=m.id and m.owner_user_id=p_user_id and q.status='CREATING';
end $$;

revoke all on function public.barrio_begin_pey_qr(uuid,text,numeric,text,text) from public, anon, authenticated;
revoke all on function public.barrio_finish_pey_qr(uuid,uuid,text,text,timestamptz) from public, anon, authenticated;
revoke all on function public.barrio_mark_pey_qr_uncertain(uuid,uuid) from public, anon, authenticated;
grant execute on function public.barrio_begin_pey_qr(uuid,text,numeric,text,text) to service_role;
grant execute on function public.barrio_finish_pey_qr(uuid,uuid,text,text,timestamptz) to service_role;
grant execute on function public.barrio_mark_pey_qr_uncertain(uuid,uuid) to service_role;
