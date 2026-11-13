-- Initial secure data model for Madrasati Bila Tanamor
-- Run only in a NEW Supabase project dedicated to this school platform.
create extension if not exists pgcrypto;

do $$ begin
  create type public.app_role as enum ('pending','school_admin','project_manager','social_worker','psychologist','teacher','guardian','student');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.report_status as enum ('new','triage','safety_plan','in_progress','follow_up','closed','referred');
exception when duplicate_object then null; end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  role public.app_role not null default 'pending',
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.classrooms (
  id uuid primary key default gen_random_uuid(),
  grade smallint not null check (grade between 1 and 6),
  class_name text not null,
  academic_year text not null,
  created_at timestamptz not null default now(),
  unique(grade,class_name,academic_year)
);

create table if not exists public.students (
  id uuid primary key default gen_random_uuid(),
  student_code text unique,
  display_name text not null,
  classroom_id uuid references public.classrooms(id) on delete set null,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.guardian_students (
  guardian_id uuid not null references public.profiles(id) on delete cascade,
  student_id uuid not null references public.students(id) on delete cascade,
  relationship text,
  primary key(guardian_id,student_id)
);

create table if not exists public.bullying_reports (
  id uuid primary key default gen_random_uuid(),
  reference_code text not null unique default upper(substr(replace(gen_random_uuid()::text,'-',''),1,8)),
  created_by uuid not null references public.profiles(id),
  incident_kind text not null check (incident_kind in ('physical','verbal','social','psychological','cyber','other','unsure')),
  location text not null,
  description text not null check (char_length(description) between 8 and 5000),
  immediate_danger boolean not null default false,
  injury_reported boolean not null default false,
  status public.report_status not null default 'new',
  assigned_to uuid references public.profiles(id) on delete set null,
  received_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);

create table if not exists public.report_student_links (
  report_id uuid not null references public.bullying_reports(id) on delete cascade,
  student_id uuid not null references public.students(id) on delete restrict,
  involvement text not null check (involvement in ('affected','alleged_behavior','witness')),
  primary key(report_id,student_id,involvement)
);

create table if not exists public.case_followups (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.bullying_reports(id) on delete cascade,
  created_by uuid not null references public.profiles(id),
  followup_at timestamptz not null default now(),
  note text not null check (char_length(note) between 2 and 3000),
  next_check_at timestamptz
);

create table if not exists public.activities (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null,
  target_grades smallint[] not null default array[1,2,3,4,5,6],
  activity_type text not null default 'classroom',
  is_published boolean not null default false,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  check (target_grades <@ array[1,2,3,4,5,6]::smallint[])
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  created_at timestamptz not null default now()
);

create or replace function public.current_app_role()
returns public.app_role
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles
  where id = auth.uid() and is_active = true
  limit 1
$$;

create or replace function public.is_school_staff()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_app_role() in
    ('school_admin','project_manager','social_worker','psychologist','teacher'),false)
$$;

alter table public.profiles enable row level security;
alter table public.classrooms enable row level security;
alter table public.students enable row level security;
alter table public.guardian_students enable row level security;
alter table public.bullying_reports enable row level security;
alter table public.report_student_links enable row level security;
alter table public.case_followups enable row level security;
alter table public.activities enable row level security;
alter table public.audit_logs enable row level security;

-- Profiles: users may see their own profile; administrators manage role assignments.
drop policy if exists "profile self read" on public.profiles;
create policy "profile self read" on public.profiles for select to authenticated using (id = auth.uid() or public.current_app_role() = 'school_admin');
drop policy if exists "profile admin update" on public.profiles;
create policy "profile admin update" on public.profiles for update to authenticated using (public.current_app_role() = 'school_admin') with check (public.current_app_role() = 'school_admin');

-- School staff can manage school directory data. Guardians see only linked children.
drop policy if exists "classrooms staff read" on public.classrooms;
create policy "classrooms staff read" on public.classrooms for select to authenticated using (public.is_school_staff());
drop policy if exists "classrooms admin manage" on public.classrooms;
create policy "classrooms admin manage" on public.classrooms for all to authenticated using (public.current_app_role() in ('school_admin','project_manager')) with check (public.current_app_role() in ('school_admin','project_manager'));

drop policy if exists "students staff read" on public.students;
create policy "students staff read" on public.students for select to authenticated using (public.is_school_staff());
drop policy if exists "students guardian linked read" on public.students;
create policy "students guardian linked read" on public.students for select to authenticated using (
  exists(select 1 from public.guardian_students gs where gs.student_id = students.id and gs.guardian_id = auth.uid())
);
drop policy if exists "students admin manage" on public.students;
create policy "students admin manage" on public.students for all to authenticated using (public.current_app_role() in ('school_admin','project_manager')) with check (public.current_app_role() in ('school_admin','project_manager'));

drop policy if exists "guardian links self or staff" on public.guardian_students;
create policy "guardian links self or staff" on public.guardian_students for select to authenticated using (guardian_id = auth.uid() or public.is_school_staff());
drop policy if exists "guardian links admin manage" on public.guardian_students;
create policy "guardian links admin manage" on public.guardian_students for all to authenticated using (public.current_app_role() in ('school_admin','project_manager')) with check (public.current_app_role() in ('school_admin','project_manager'));

-- Reports: authenticated users may submit; only the submitter and authorized staff may read.
drop policy if exists "reports submit" on public.bullying_reports;
create policy "reports submit" on public.bullying_reports for insert to authenticated with check (created_by = auth.uid());
drop policy if exists "reports submitter or staff read" on public.bullying_reports;
create policy "reports submitter or staff read" on public.bullying_reports for select to authenticated using (created_by = auth.uid() or public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist'));
drop policy if exists "reports authorized staff update" on public.bullying_reports;
create policy "reports authorized staff update" on public.bullying_reports for update to authenticated using (public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist')) with check (public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist'));

drop policy if exists "report links staff only" on public.report_student_links;
create policy "report links staff only" on public.report_student_links for all to authenticated using (public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist')) with check (public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist'));

drop policy if exists "followups staff read" on public.case_followups;
create policy "followups staff read" on public.case_followups for select to authenticated using (public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist'));
drop policy if exists "followups staff create" on public.case_followups;
create policy "followups staff create" on public.case_followups for insert to authenticated with check (created_by = auth.uid() and public.current_app_role() in ('school_admin','project_manager','social_worker','psychologist'));

drop policy if exists "activities published or staff read" on public.activities;
create policy "activities published or staff read" on public.activities for select to authenticated using (is_published = true or public.is_school_staff());
drop policy if exists "activities staff manage" on public.activities;
create policy "activities staff manage" on public.activities for all to authenticated using (public.current_app_role() in ('school_admin','project_manager','social_worker','teacher')) with check (public.current_app_role() in ('school_admin','project_manager','social_worker','teacher'));

drop policy if exists "audit staff admin read" on public.audit_logs;
create policy "audit staff admin read" on public.audit_logs for select to authenticated using (public.current_app_role() = 'school_admin');

create index if not exists idx_students_classroom on public.students(classroom_id);
create index if not exists idx_reports_status_received on public.bullying_reports(status,received_at desc);
create index if not exists idx_reports_creator on public.bullying_reports(created_by,received_at desc);
create index if not exists idx_followups_report on public.case_followups(report_id,followup_at desc);

comment on table public.bullying_reports is 'Sensitive child-protection reports. Never expose through public pages or anonymous queries.';
comment on table public.report_student_links is 'Restricted links between reports and student records; staff-only access.';
