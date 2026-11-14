-- Demo flow: multiple open merchant QR requests are allowed. Cancellation is
-- recorded in BARRIO only; Pey's published API has no QR revocation endpoint.
drop index if exists public.barrio_pey_qr_one_open_request_per_merchant;
alter table public.barrio_pey_qr_requests drop constraint if exists barrio_pey_qr_requests_status_check;
alter table public.barrio_pey_qr_requests add constraint barrio_pey_qr_requests_status_check
  check (status in ('CREATING','PENDING','PAID','UNCERTAIN','EXPIRED','CANCELLED'));

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
  insert into public.barrio_pey_qr_requests(merchant_id,idempotency_key,amount_mxn,concept,num_ref,status)
    values(p_merchant_id,p_key,p_amount,trim(p_concept),p_num_ref,'CREATING') returning * into v_request;
  return jsonb_build_object('should_create',true,'request_id',v_request.id,'merchant_id',p_merchant_id,'bank_account_id',v_bank.pey_bank_account_id,'status',v_request.status,'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref);
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
  insert into public.barrio_pey_qr_requests(merchant_id,idempotency_key,amount_mxn,concept,num_ref,status)
    values(v_order.merchant_id,p_key,v_order.total_mxn,'Pedido BARRIO',p_num_ref,'CREATING') returning * into v_request;
  update public.barrio_orders set pey_qr_request_id=v_request.id where id=v_order.id;
  return jsonb_build_object('should_create',true,'request_id',v_request.id,'merchant_id',v_order.merchant_id,'bank_account_id',v_bank.pey_bank_account_id,'status',v_request.status,'amount_mxn',v_request.amount_mxn,'concept',v_request.concept,'num_ref',v_request.num_ref);
end $$;

create or replace function public.barrio_cancel_merchant_pey_qr(p_user_id uuid,p_request_id uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_request public.barrio_pey_qr_requests%rowtype;
begin
  select q.* into v_request from public.barrio_pey_qr_requests q
    join public.barrio_merchants m on m.id=q.merchant_id
    where q.id=p_request_id and m.owner_user_id=p_user_id and m.active
    for update of q;
  if not found then raise exception 'qr_request_not_found' using errcode='P0002'; end if;
  if exists(select 1 from public.barrio_orders where pey_qr_request_id=v_request.id) then
    raise exception 'checkout_qr_cancellation_not_supported' using errcode='55000';
  end if;
  if v_request.status='PENDING' and v_request.expires_at<=now() then
    update public.barrio_pey_qr_requests set status='EXPIRED' where id=v_request.id;
    return jsonb_build_object('request_id',v_request.id,'status','EXPIRED');
  end if;
  if v_request.status<>'PENDING' then raise exception 'qr_not_cancellable' using errcode='55000'; end if;
  update public.barrio_pey_qr_requests set status='CANCELLED' where id=v_request.id;
  return jsonb_build_object('request_id',v_request.id,'status','CANCELLED');
end $$;

revoke all on function public.barrio_cancel_merchant_pey_qr(uuid,uuid) from public,anon,authenticated;
grant execute on function public.barrio_cancel_merchant_pey_qr(uuid,uuid) to service_role;
