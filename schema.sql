-- Gather shared grocery list: run this entire script in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.households (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'Our groceries',
  invite_code text not null unique default upper(substr(encode(gen_random_bytes(8),'hex'),1,8)),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Member',
  created_at timestamptz not null default now()
);
create table if not exists public.household_members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (household_id,user_id)
);
insert into public.profiles(id,display_name) select m.user_id,coalesce(nullif(split_part(u.email,'@',1),''),'Member') from public.household_members m join auth.users u on u.id=m.user_id on conflict(id) do nothing;
alter table public.household_members drop constraint if exists household_members_user_id_fkey;
alter table public.household_members add constraint household_members_user_id_fkey foreign key(user_id) references public.profiles(id) on delete cascade;

create table if not exists public.shopping_items (
  id uuid primary key default gen_random_uuid(),
  household_id uuid not null references public.households(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 120),
  quantity text not null default '',
  is_bought boolean not null default false,
  added_by uuid not null references auth.users(id) on delete cascade,
  bought_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  bought_at timestamptz
);
create index if not exists shopping_items_household_created on public.shopping_items(household_id,created_at);

create or replace function public.is_household_member(target uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.household_members where household_id=target and user_id=auth.uid()) $$;

create or replace function public.create_household(household_name text)
returns jsonb language plpgsql security definer set search_path=public
as $$
declare h public.households;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  insert into public.households(name,created_by) values (left(coalesce(nullif(trim(household_name),''),'Our groceries'),50),auth.uid()) returning * into h;
  insert into public.profiles(id,display_name) values(auth.uid(),coalesce(nullif(split_part(auth.jwt()->>'email','@',1),''),'Member')) on conflict(id) do nothing;
  insert into public.household_members(household_id,user_id) values(h.id,auth.uid());
  return jsonb_build_object('id',h.id,'name',h.name,'invite_code',h.invite_code);
end $$;

create or replace function public.join_household(code text)
returns uuid language plpgsql security definer set search_path=public
as $$
declare h public.households;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select * into h from public.households where invite_code=upper(trim(code));
  if h.id is null then raise exception 'Invite code not found'; end if;
  insert into public.profiles(id,display_name) values(auth.uid(),coalesce(nullif(split_part(auth.jwt()->>'email','@',1),''),'Member')) on conflict(id) do nothing;
  insert into public.household_members(household_id,user_id) values(h.id,auth.uid()) on conflict do nothing;
  return h.id;
end $$;

alter table public.households enable row level security;
alter table public.profiles enable row level security;
alter table public.household_members enable row level security;
alter table public.shopping_items enable row level security;
drop policy if exists "Members can view their households" on public.households;
create policy "Members can view their households" on public.households for select to authenticated using(public.is_household_member(id));
drop policy if exists "Members can view household members" on public.household_members;
create policy "Members can view household members" on public.household_members for select to authenticated using(public.is_household_member(household_id));
drop policy if exists "Users can view member profiles" on public.profiles;
create policy "Users can view member profiles" on public.profiles for select to authenticated using (id=auth.uid() or exists(select 1 from public.household_members a join public.household_members b using(household_id) where a.user_id=auth.uid() and b.user_id=profiles.id));
drop policy if exists "Members can view list items" on public.shopping_items;
create policy "Members can view list items" on public.shopping_items for select to authenticated using(public.is_household_member(household_id));
drop policy if exists "Members can add list items" on public.shopping_items;
create policy "Members can add list items" on public.shopping_items for insert to authenticated with check(public.is_household_member(household_id) and added_by=auth.uid());
drop policy if exists "Members can update list items" on public.shopping_items;
create policy "Members can update list items" on public.shopping_items for update to authenticated using(public.is_household_member(household_id)) with check(public.is_household_member(household_id));
drop policy if exists "Members can delete list items" on public.shopping_items;
create policy "Members can delete list items" on public.shopping_items for delete to authenticated using(public.is_household_member(household_id));

grant usage on schema public to authenticated;
grant select on public.households,public.household_members,public.profiles to authenticated;
grant select,insert,update,delete on public.shopping_items to authenticated;
grant execute on function public.create_household(text) to authenticated;
grant execute on function public.join_household(text) to authenticated;

do $$ begin
  alter publication supabase_realtime add table public.shopping_items;
exception when duplicate_object then null;
when undefined_object then raise notice 'Create the supabase_realtime publication in Supabase before enabling realtime.';
end $$;



