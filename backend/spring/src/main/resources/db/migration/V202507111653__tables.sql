SET time_zone = "+00:00";
SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci';

create table login (
    id              bigint          primary key,
    created         timestamp       not null default now(),
    modified        timestamp       not null default now() ON UPDATE CURRENT_TIMESTAMP,
    enabled         boolean         not null default 1,
    failures        smallint        not null default 0,
    roles           bigint          not null default 4,
    username        varchar(50)     not null unique,
    email           varchar(320)        null unique,
    password        varchar(255)        null
);

create table persistent_logins (
    series          varchar(64)     primary key,
    username        varchar(64)     not null,
    token           varchar(64)     not null,
    last_used       datetime        not null
);
