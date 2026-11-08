-- Keep definitive Pey HTTP rejections separate from timeouts/5xx responses.
-- Only a rejection confirmed by an HTTP response can release the merchant for a corrected retry.
begin;

alter table public.barrio_pey_registration_attempts
  drop constraint if exists barrio_pey_registration_attempts_state_check;
alter table public.barrio_pey_registration_attempts
  add constraint barrio_pey_registration_attempts_state_check
  check (state in ('SOLICITANDO','REGISTRADA','INCIERTA','RECHAZADA'));

create or replace function public.barrio_mark_pey_attempt_rejected(
  p_user_id uuid, p_merchant_id uuid, p_key text
) returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  update public.barrio_pey_registration_attempts a
  set state='RECHAZADA'
  from public.barrio_merchants m
  where a.merchant_id=p_merchant_id and a.idempotency_key=p_key
    and a.state='SOLICITANDO'
    and m.id=p_merchant_id and m.owner_user_id=p_user_id;
  if not found then raise exception 'pey_attempt_not_found' using errcode='P0002'; end if;
end $$;

revoke all on function public.barrio_mark_pey_attempt_rejected(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.barrio_mark_pey_attempt_rejected(uuid,uuid,text) to service_role;

commit;
