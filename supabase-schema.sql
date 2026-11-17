create extension if not exists "pgcrypto";

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  role text not null default 'user',
  credits integer not null default 0,
  free_rbxl_vouchers integer not null default 0,
  free_rbxm_vouchers integer not null default 0,
  roblox_user_id text default '',
  roblox_universe_id text default '',
  roblox_place_id text default '',
  encrypted_api_key text default '',
  api_key_hint text default '',
  created_at timestamptz default now()
);

create table if not exists public.upload_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.users(id) on delete cascade,
  username text not null,
  file_name text not null,
  file_type text not null,
  file_size_bytes integer not null,
  upload_mode text not null,
  result_id text not null,
  is_public boolean default false,
  credit_used integer not null default 0,
  used_voucher boolean default false,
  created_at timestamptz default now()
);