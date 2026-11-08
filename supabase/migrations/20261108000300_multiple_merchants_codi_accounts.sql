-- Demo limit: up to five business profiles per Barrio user, each with its own CoDi account.
alter table public.barrio_merchants drop constraint if exists barrio_merchants_owner_user_id_key;
alter table public.barrio_merchants add column if not exists creation_key uuid;
create index if not exists barrio_merchants_owner_user_active_idx
  on public.barrio_merchants(owner_user_id, active, created_at);
create unique index if not exists barrio_merchants_owner_creation_key_uq
  on public.barrio_merchants(owner_user_id, creation_key) where creation_key is not null;

create or replace function public.barrio_create_merchant(
  p_user_id uuid, p_name text, p_description text, p_neighborhood_id bigint,
  p_category_id bigint, p_show_in_directory boolean
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_merchant_id uuid; v_count integer;
begin
  perform 1 from public.barrio_users where id=p_user_id and active and 'Comercio'=any(roles) for update;
  if not found then raise exception 'merchant_role_required' using errcode='42501'; end if;
  select count(*) into v_count from public.barrio_merchants where owner_user_id=p_user_id and active;
  if v_count >= 5 then raise exception 'merchant_limit_reached' using errcode='54000'; end if;
  insert into public.barrio_merchants(owner_user_id,name,description,neighborhood_id,show_in_directory)
  values(p_user_id,trim(p_name),nullif(trim(p_description),''),p_neighborhood_id,p_show_in_directory)
  returning id into v_merchant_id;
  insert into public.barrio_merchant_categories(merchant_id,category_id) values(v_merchant_id,p_category_id);
  return jsonb_build_object('merchant_id',v_merchant_id);
end $$;

create or replace function public.barrio_create_merchant_idempotent(
  p_user_id uuid, p_name text, p_description text, p_neighborhood_id bigint,
  p_category_id bigint, p_show_in_directory boolean, p_creation_key uuid
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_merchant_id uuid; v_count integer;
begin
  if p_creation_key is null then raise exception 'merchant_creation_key_required' using errcode='22023'; end if;
  perform 1 from public.barrio_users where id=p_user_id and active and 'Comercio'=any(roles) for update;
  if not found then raise exception 'merchant_role_required' using errcode='42501'; end if;
  select id into v_merchant_id from public.barrio_merchants where owner_user_id=p_user_id and creation_key=p_creation_key;
  if v_merchant_id is not null then return jsonb_build_object('merchant_id',v_merchant_id); end if;
  select count(*) into v_count from public.barrio_merchants where owner_user_id=p_user_id and active;
  if v_count >= 5 then raise exception 'merchant_limit_reached' using errcode='54000'; end if;
  insert into public.barrio_merchants(owner_user_id,name,description,neighborhood_id,show_in_directory,creation_key)
  values(p_user_id,trim(p_name),nullif(trim(p_description),''),p_neighborhood_id,p_show_in_directory,p_creation_key)
  returning id into v_merchant_id;
  insert into public.barrio_merchant_categories(merchant_id,category_id) values(v_merchant_id,p_category_id);
  return jsonb_build_object('merchant_id',v_merchant_id);
end $$;

create or replace function public.barrio_save_payment_methods_for_merchant(
  p_user_id uuid, p_merchant_id uuid, p_methods jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_result jsonb;
begin
  if not exists(select 1 from public.barrio_merchants where id=p_merchant_id and owner_user_id=p_user_id and active) then
    raise exception 'merchant_profile_required' using errcode='23503';
  end if;
  insert into public.barrio_merchant_payment_methods(merchant_id,method_code,selected,enabled,configuration_status)
  select p_merchant_id, m.code, m.selected,
    (m.code='EFECTIVO' and m.selected),
    case when not m.selected then 'PENDIENTE'
      when m.code='EFECTIVO' then 'DISPONIBLE'
      when m.code='PEY_CODI' then 'REQUIERE_PEY'
      when m.code='NFC' then 'PROXIMAMENTE'
      else 'PENDIENTE' end
  from jsonb_to_recordset(p_methods) as m(code text,selected boolean)
  on conflict(merchant_id,method_code) do update set
    selected=excluded.selected,enabled=excluded.enabled,
    configuration_status=excluded.configuration_status,updated_at=now();
  select coalesce(jsonb_agg(jsonb_build_object('code',pm.code,'name',pm.name,'selected',mp.selected,'enabled',mp.enabled,'configurationStatus',mp.configuration_status) order by pm.sort_order),'[]'::jsonb)
  into v_result from public.barrio_merchant_payment_methods mp
  join public.barrio_payment_methods pm on pm.code=mp.method_code where mp.merchant_id=p_merchant_id;
  return v_result;
end $$;

create or replace function public.barrio_begin_pey_registration_for_merchant(
  p_user_id uuid, p_merchant_id uuid, p_key text, p_clabe_last4 char(4)
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_account public.barrio_pey_bank_accounts%rowtype; v_attempt public.barrio_pey_registration_attempts%rowtype;
begin
  if p_key is null or length(p_key)<16 or length(p_key)>100 then raise exception 'idempotency_key_required' using errcode='22023'; end if;
  perform 1 from public.barrio_merchants where id=p_merchant_id and owner_user_id=p_user_id and active for update;
  if not found then raise exception 'merchant_profile_required' using errcode='23503'; end if;
  select * into v_account from public.barrio_pey_bank_accounts where merchant_id=p_merchant_id;
  if found then return jsonb_build_object('should_register',false,'merchant_id',p_merchant_id,'bank_account_id',v_account.pey_bank_account_id,'status',v_account.codi_status,'clabe_last4',v_account.clabe_last4); end if;
  select * into v_attempt from public.barrio_pey_registration_attempts where merchant_id=p_merchant_id and state in ('SOLICITANDO','INCIERTA') order by created_at desc limit 1;
  if found then return jsonb_build_object('should_register',false,'merchant_id',p_merchant_id,'state',v_attempt.state,'clabe_last4',v_attempt.clabe_last4); end if;
  select * into v_attempt from public.barrio_pey_registration_attempts where merchant_id=p_merchant_id and idempotency_key=p_key;
  if found then return jsonb_build_object('should_register',false,'merchant_id',p_merchant_id,'state',v_attempt.state,'clabe_last4',v_attempt.clabe_last4); end if;
  insert into public.barrio_pey_registration_attempts(merchant_id,idempotency_key,clabe_last4,state)
  values(p_merchant_id,p_key,p_clabe_last4,'SOLICITANDO');
  return jsonb_build_object('should_register',true,'merchant_id',p_merchant_id,'clabe_last4',p_clabe_last4);
end $$;

create or replace function public.barrio_begin_pey_qr(
  p_user_id uuid, p_merchant_id uuid, p_key text, p_amount numeric, p_concept text, p_num_ref text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_bank public.barrio_pey_bank_accounts%rowtype; v_existing public.barrio_pey_qr_requests%rowtype; v_request public.barrio_pey_qr_requests%rowtype;
begin
  if p_key is null or length(p_key)<16 or length(p_key)>100 then raise exception 'idempotency_key_required' using errcode='22023'; end if;
  if p_amount is null or p_amount<=0 or p_amount>1000000 then raise exception 'invalid_amount' using errcode='22023'; end if;
  if p_concept is null or length(trim(p_concept))<1 or length(p_concept)>100 then raise exception 'invalid_concept' using errcode='22023'; end if;
  if p_num_ref is null or p_num_ref !~ '^[0-9]{1,7}$' then raise exception 'invalid_reference' using errcode='22023'; end if;
  perform 1 from public.barrio_merchants where id=p_merchant_id and owner_user_id=p_user_id and active for update;
  if not found then raise exception 'merchant_profile_required' using errcode='23503'; end if;
  select * into v_bank from public.barrio_pey_bank_accounts where merchant_id=p_merchant_id;
  if not found then raise exception 'bank_account_not_registered' using errcode='23503'; end if;
  if v_bank.codi_status<>'ACTIVE' then raise exception 'merchant_bank_account_not_active' using errcode='55000'; end if;
  select * into v_existing from public.barrio_pey_qr_requests where merchant_id=p_merchant_id and idempotency_key=p_key;
  if found then
    if v_existing.amount_mxn<>p_amount or v_existing.concept<>trim(p_concept) then raise exception 'idempotency_key_conflict' using errcode='23505'; end if;
    return jsonb_build_object('should_create',false,'request_id',v_existing.id,'status',v_existing.status,'pey_qr_id',v_existing.pey_qr_id,'qr_string',v_existing.qr_string,'amount_mxn',v_existing.amount_mxn,'concept',v_existing.concept,'num_ref',v_existing.num_ref,'created_at',v_existing.created_at,'expires_at',v_existing.expires_at);
  end if;
  update public.barrio_pey_qr_requests set status='EXPIRED' where merchant_id=p_merchant_id and status='PENDING' and expires_at<=now();
  if exists(select 1 from public.barrio_pey_qr_requests where merchant_id=p_merchant_id and status in ('CREATING','PENDING','UNCERTAIN')) then raise exception 'active_qr_exists' using errcode='55000'; end if;
  insert into public.barrio_pey_qr_requests(merchant_id,idempotency_key,amount_mxn,concept,num_ref,status)
  values(p_merchant_id,p_key,p_amount,trim(p_concept),p_num_ref,'CREATING') returning * into v_request;
  return jsonb_build_object('should_create',true,'request_id',v_request.id,'merchant_id',p_merchant_id,'bank_account_id',v_bank.pey_bank_account_id,'status',v_request.status,'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref);
end $$;

revoke all on function public.barrio_save_payment_methods_for_merchant(uuid,uuid,jsonb) from public, anon, authenticated;
revoke all on function public.barrio_create_merchant_idempotent(uuid,text,text,bigint,bigint,boolean,uuid) from public, anon, authenticated;
revoke all on function public.barrio_begin_pey_registration_for_merchant(uuid,uuid,text,char) from public, anon, authenticated;
revoke all on function public.barrio_begin_pey_qr(uuid,uuid,text,numeric,text,text) from public, anon, authenticated;
grant execute on function public.barrio_save_payment_methods_for_merchant(uuid,uuid,jsonb) to service_role;
grant execute on function public.barrio_create_merchant_idempotent(uuid,text,text,bigint,bigint,boolean,uuid) to service_role;
grant execute on function public.barrio_begin_pey_registration_for_merchant(uuid,uuid,text,char) to service_role;
grant execute on function public.barrio_begin_pey_qr(uuid,uuid,text,numeric,text,text) to service_role;
