-- =====================================================================
--  V TEXAS RP | بوابة التقديم على الإدارة  —  إعداد قاعدة بيانات Supabase
--  شغّل هذا الملف كاملاً مرة واحدة من:  Supabase Dashboard → SQL Editor → New query → Run
--  (آمن لإعادة التشغيل أكثر من مرة)
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 1) الجداول
-- ---------------------------------------------------------------------
create table if not exists public.applications (
  id             text primary key,                 -- رقم التقديم VTX-2026-XXXX
  name           text not null,
  age            int  not null check (age between 10 and 99),
  discord_tag    text not null,
  discord_id     text not null,
  char_name      text not null,
  country        text not null,
  department     text,
  hours          text,
  shift          text,
  mic            text,
  exp            text,
  why            text,
  scenario1      text,
  scenario2      text,
  quiz_score     int  not null default 0 check (quiz_score between 0 and 100),
  quiz_correct   int  not null default 0 check (quiz_correct between 0 and 4),
  status         text not null default 'قيد المراجعة'
                 check (status in ('قيد المراجعة','مؤهل للمقابلة','مقبول','مرفوض')),
  admin_note     text not null default '',
  created_label  text,                              -- تاريخ العرض (YYYY-MM-DD HH:MM)
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists applications_discord_tag_idx on public.applications (lower(discord_tag));
create index if not exists applications_discord_id_idx  on public.applications (lower(discord_id));
create index if not exists applications_created_idx     on public.applications (created_at desc);

-- كلمات مرور لوحة الإدارة (مخزّنة مشفّرة bcrypt — وليست نصاً صريحاً)
create table if not exists public.admin_passwords (
  id   bigint generated always as identity primary key,
  hash text not null
);

-- سجل محاولات الدخول الفاشلة (حماية من التخمين)
create table if not exists public.admin_failures (
  at timestamptz not null default now()
);
create index if not exists admin_failures_at_idx on public.admin_failures (at);

-- ---------------------------------------------------------------------
-- 2) الحماية: RLS مفعّل بدون أي سياسة = لا أحد يقرأ/يكتب الجداول مباشرة
--    كل الوصول يتم عبر الدوال بالأسفل فقط
-- ---------------------------------------------------------------------
alter table public.applications    enable row level security;
alter table public.admin_passwords enable row level security;
alter table public.admin_failures  enable row level security;

revoke all on public.applications    from anon, authenticated;
revoke all on public.admin_passwords from anon, authenticated;
revoke all on public.admin_failures  from anon, authenticated;

-- ---------------------------------------------------------------------
-- 3) كلمة مرور الإدارة (نفس الكلمات القديمة بالموقع)
--    لتغييرها لاحقاً: احذف الصفوف وأضف كلمة جديدة بنفس الطريقة
-- ---------------------------------------------------------------------
truncate public.admin_passwords;
insert into public.admin_passwords (hash)
select extensions.crypt(p, extensions.gen_salt('bf'))
from unnest(array[
  '/𝑽 𝑻𝑬𝑿𝑨𝑺 𝑹𝑷 1710199',
  '𝑽 𝑻𝑬𝑿𝑨𝑺 𝑹𝑷 1710199',
  '/V TEXAS RP 1710199',
  'V TEXAS RP 1710199'
]) as p;

-- ---------------------------------------------------------------------
-- 4) دوال مساعدة داخلية (غير متاحة للعامة)
-- ---------------------------------------------------------------------
create or replace function public._check_admin(p_pass text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_ok boolean;
begin
  if (select count(*) from public.admin_failures where at > now() - interval '10 minutes') >= 15 then
    raise exception 'too_many_attempts';
  end if;

  select exists (
    select 1 from public.admin_passwords
    where hash = extensions.crypt(btrim(coalesce(p_pass, '')), hash)
  ) into v_ok;

  if not v_ok then
    insert into public.admin_failures default values;
    delete from public.admin_failures where at < now() - interval '1 day';
  end if;
  return v_ok;
end;
$$;

create or replace function public._app_json(a public.applications)
returns jsonb
language sql
immutable
set search_path = public
as $$
  select jsonb_build_object(
    'id',          a.id,
    'name',        a.name,
    'age',         a.age,
    'discordTag',  a.discord_tag,
    'discordId',   a.discord_id,
    'charName',    a.char_name,
    'country',     a.country,
    'department',  a.department,
    'hours',       a.hours,
    'shift',       a.shift,
    'mic',         a.mic,
    'exp',         a.exp,
    'why',         a.why,
    'scenario1',   a.scenario1,
    'scenario2',   a.scenario2,
    'quizScore',   a.quiz_score,
    'quizCorrect', a.quiz_correct,
    'status',      a.status,
    'adminNote',   a.admin_note,
    'createdAt',   coalesce(a.created_label, to_char(a.created_at, 'YYYY-MM-DD HH24:MI')),
    'updatedAt',   a.updated_at
  );
$$;

-- ---------------------------------------------------------------------
-- 5) دوال عامة (للزوار): تقديم طلب / استعلام / إحصائية
-- ---------------------------------------------------------------------
create or replace function public.submit_application(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id    text;
  v_try   int := 0;
  v_age   int;
  v_qc    int;
  v_label text;
begin
  if p is null or jsonb_typeof(p) <> 'object' then
    raise exception 'invalid_payload';
  end if;

  v_age := nullif(p->>'age','')::int;
  if coalesce(btrim(p->>'name'),'') = '' or v_age is null or v_age < 14
     or coalesce(btrim(p->>'discordTag'),'') = '' or coalesce(btrim(p->>'discordId'),'') = ''
     or coalesce(btrim(p->>'charName'),'') = '' or coalesce(btrim(p->>'country'),'') = '' then
    raise exception 'missing_fields';
  end if;

  -- حماية من السبام: 3 طلبات كحد أقصى بالساعة لنفس معرّف الديسكورد
  if (select count(*) from public.applications
      where lower(discord_id) = lower(btrim(p->>'discordId'))
        and created_at > now() - interval '1 hour') >= 3 then
    raise exception 'rate_limited';
  end if;

  v_qc    := greatest(0, least(4, coalesce(nullif(p->>'quizCorrect','')::int, 0)));
  v_label := nullif(left(coalesce(p->>'createdAt',''), 32), '');

  loop
    v_try := v_try + 1;
    v_id := 'VTX-2026-' || (1100 + floor(random() * 8800))::int::text;
    if v_try > 30 then
      v_id := 'VTX-2026-' || (10000 + floor(random() * 89999))::int::text;
    end if;
    exit when not exists (select 1 from public.applications where id = v_id);
    if v_try > 60 then raise exception 'id_generation_failed'; end if;
  end loop;

  insert into public.applications (
    id, name, age, discord_tag, discord_id, char_name, country, department,
    hours, shift, mic, exp, why, scenario1, scenario2,
    quiz_score, quiz_correct, status, admin_note, created_label
  ) values (
    v_id,
    left(btrim(p->>'name'), 120),
    v_age,
    left(btrim(p->>'discordTag'), 80),
    left(btrim(p->>'discordId'), 40),
    left(btrim(p->>'charName'), 120),
    left(btrim(p->>'country'), 80),
    left(coalesce(p->>'department',''), 120),
    left(coalesce(p->>'hours',''), 120),
    left(coalesce(p->>'shift',''), 120),
    left(coalesce(p->>'mic',''), 120),
    left(coalesce(p->>'exp',''), 4000),
    left(coalesce(p->>'why',''), 4000),
    left(coalesce(p->>'scenario1',''), 4000),
    left(coalesce(p->>'scenario2',''), 4000),
    round(v_qc * 25.0)::int,
    v_qc,
    'قيد المراجعة',
    'تم استلام طلبك بنجاح وهو الآن قيد المراجعة لدى القيادة العليا. احتفظ برقم التقديم (' || v_id || ') واستعلم عنه باستمرار.',
    v_label
  );

  return (select public._app_json(a) from public.applications a where a.id = v_id);
end;
$$;

-- الاستعلام عن طلب: يرجّع الحقول اللازمة فقط (بدون إجابات المتقدم)
create or replace function public.track_application(q text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_q text := lower(btrim(coalesce(q, '')));
  a   public.applications;
begin
  if v_q = '' or length(v_q) > 100 then return null; end if;

  select * into a
  from public.applications
  where lower(id) = v_q or lower(discord_tag) = v_q or lower(discord_id) = v_q
  order by created_at desc
  limit 1;

  if not found then return null; end if;

  return jsonb_build_object(
    'id',         a.id,
    'name',       a.name,
    'age',        a.age,
    'discordTag', a.discord_tag,
    'department', a.department,
    'status',     a.status,
    'adminNote',  a.admin_note,
    'createdAt',  coalesce(a.created_label, to_char(a.created_at, 'YYYY-MM-DD HH24:MI'))
  );
end;
$$;

create or replace function public.public_stats()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select jsonb_build_object('total', (select count(*) from public.applications));
$$;

-- ---------------------------------------------------------------------
-- 6) دوال لوحة الإدارة (تتطلب كلمة المرور في كل استدعاء)
--    عند الخطأ ترجع {"error":"unauthorized"} بدل raise حتى يُسجَّل سجل المحاولات الفاشلة
-- ---------------------------------------------------------------------
create or replace function public.admin_login(p_pass text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  return public._check_admin(p_pass);
end;
$$;

create or replace function public.admin_list_applications(p_pass text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public._check_admin(p_pass) then return jsonb_build_object('error','unauthorized'); end if;
  return coalesce(
    (select jsonb_agg(public._app_json(a) order by a.created_at desc) from public.applications a),
    '[]'::jsonb
  );
end;
$$;

create or replace function public.admin_update_application(
  p_pass text, p_id text, p_status text, p_note text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  a public.applications;
begin
  if not public._check_admin(p_pass) then return jsonb_build_object('error','unauthorized'); end if;
  if p_status not in ('قيد المراجعة','مؤهل للمقابلة','مقبول','مرفوض') then
    raise exception 'invalid_status';
  end if;

  update public.applications
     set status = p_status,
         admin_note = left(coalesce(p_note, ''), 2000),
         updated_at = now()
   where id = p_id
   returning * into a;

  if not found then raise exception 'not_found'; end if;
  return public._app_json(a);
end;
$$;

create or replace function public.admin_delete_all(p_pass text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  n int;
begin
  if not public._check_admin(p_pass) then return jsonb_build_object('error','unauthorized'); end if;
  delete from public.applications where true;
  get diagnostics n = row_count;
  return jsonb_build_object('deleted', n);
end;
$$;

-- استيراد نسخة احتياطية JSON (ملف التصدير القديم من الموقع)
create or replace function public.admin_import_applications(p_pass text, p_items jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  it jsonb;
  n  int := 0;
  v_ts timestamptz;
  v_label text;
  v_status text;
begin
  if not public._check_admin(p_pass) then return jsonb_build_object('error','unauthorized'); end if;
  if p_items is null or jsonb_typeof(p_items) <> 'array' then raise exception 'invalid_payload'; end if;

  for it in select * from jsonb_array_elements(p_items) loop
    continue when coalesce(it->>'id','') = '';

    v_label := nullif(left(coalesce(it->>'createdAt',''), 32), '');
    begin
      v_ts := coalesce(v_label::timestamptz, now());
    exception when others then
      v_ts := now();
    end;

    v_status := coalesce(it->>'status', 'قيد المراجعة');
    if v_status not in ('قيد المراجعة','مؤهل للمقابلة','مقبول','مرفوض') then
      v_status := 'قيد المراجعة';
    end if;

    insert into public.applications (
      id, name, age, discord_tag, discord_id, char_name, country, department,
      hours, shift, mic, exp, why, scenario1, scenario2,
      quiz_score, quiz_correct, status, admin_note, created_label, created_at
    ) values (
      left(it->>'id', 40),
      left(coalesce(it->>'name',''), 120),
      coalesce(nullif(it->>'age','')::int, 18),
      left(coalesce(it->>'discordTag',''), 80),
      left(coalesce(it->>'discordId',''), 40),
      left(coalesce(it->>'charName',''), 120),
      left(coalesce(it->>'country',''), 80),
      left(coalesce(it->>'department',''), 120),
      left(coalesce(it->>'hours',''), 120),
      left(coalesce(it->>'shift',''), 120),
      left(coalesce(it->>'mic',''), 120),
      left(coalesce(it->>'exp',''), 4000),
      left(coalesce(it->>'why',''), 4000),
      left(coalesce(it->>'scenario1',''), 4000),
      left(coalesce(it->>'scenario2',''), 4000),
      greatest(0, least(100, coalesce(nullif(it->>'quizScore','')::int, 0))),
      greatest(0, least(4,   coalesce(nullif(it->>'quizCorrect','')::int, 0))),
      v_status,
      left(coalesce(it->>'adminNote',''), 2000),
      v_label,
      v_ts
    )
    on conflict (id) do update set
      name = excluded.name, age = excluded.age,
      discord_tag = excluded.discord_tag, discord_id = excluded.discord_id,
      char_name = excluded.char_name, country = excluded.country,
      department = excluded.department, hours = excluded.hours,
      shift = excluded.shift, mic = excluded.mic, exp = excluded.exp,
      why = excluded.why, scenario1 = excluded.scenario1, scenario2 = excluded.scenario2,
      quiz_score = excluded.quiz_score, quiz_correct = excluded.quiz_correct,
      status = excluded.status, admin_note = excluded.admin_note,
      created_label = excluded.created_label, updated_at = now();
    n := n + 1;
  end loop;
  return jsonb_build_object('imported', n);
end;
$$;

-- ---------------------------------------------------------------------
-- 7) الصلاحيات: الزوار (anon) يستدعون الدوال فقط
-- ---------------------------------------------------------------------
revoke all on function public._check_admin(text)                         from public, anon, authenticated;
revoke all on function public._app_json(public.applications)             from public, anon, authenticated;

revoke all on function public.submit_application(jsonb)                  from public;
revoke all on function public.track_application(text)                    from public;
revoke all on function public.public_stats()                             from public;
revoke all on function public.admin_login(text)                          from public;
revoke all on function public.admin_list_applications(text)             from public;
revoke all on function public.admin_update_application(text,text,text,text) from public;
revoke all on function public.admin_delete_all(text)                     from public;
revoke all on function public.admin_import_applications(text,jsonb)      from public;

grant execute on function public.submit_application(jsonb)                  to anon, authenticated;
grant execute on function public.track_application(text)                    to anon, authenticated;
grant execute on function public.public_stats()                             to anon, authenticated;
grant execute on function public.admin_login(text)                          to anon, authenticated;
grant execute on function public.admin_list_applications(text)              to anon, authenticated;
grant execute on function public.admin_update_application(text,text,text,text) to anon, authenticated;
grant execute on function public.admin_delete_all(text)                     to anon, authenticated;
grant execute on function public.admin_import_applications(text,jsonb)      to anon, authenticated;

-- إعادة تحميل كاش الـ API
notify pgrst, 'reload schema';
