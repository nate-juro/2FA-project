create table if not exists users (
    user_id integer primary key autoincrement,
    username text unique not null,
    email text unique not null,
    password_hash text not null,
    totp_secret text,
    totp_confirmed int not null default 0,
    failed_attempts int not null default 0,
    locked_until datetime,
    created_at datetime default current_timestamp
);
 
create table if not exists login_log (
    log_id integer primary key autoincrement,
    username text not null,
    event text not null,
    ip_address text,
    created_at datetime not null default current_timestamp
);