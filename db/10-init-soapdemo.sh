#!/bin/bash
# Runs once, on first initialisation of the Postgres data directory.
# Creates a separate "soapdemo" database with a small user directory that the
# SOAP gateway queries. authentik keeps its own database untouched.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c "CREATE DATABASE soapdemo;"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "soapdemo" <<'EOSQL'
CREATE TABLE app_user (
    username     text PRIMARY KEY,
    display_name text NOT NULL,
    email        text NOT NULL,
    is_active    boolean NOT NULL DEFAULT true
);

CREATE TABLE app_group (
    name        text PRIMARY KEY,
    description text NOT NULL DEFAULT ''
);

CREATE TABLE user_group (
    username   text NOT NULL REFERENCES app_user(username) ON DELETE CASCADE,
    group_name text NOT NULL REFERENCES app_group(name)    ON DELETE CASCADE,
    PRIMARY KEY (username, group_name)
);

INSERT INTO app_user (username, display_name, email) VALUES
    ('alice', 'Alice Anderson', 'alice@example.com'),
    ('bob',   'Bob Baker',      'bob@example.com'),
    ('carol', 'Carol Chen',     'carol@example.com');

INSERT INTO app_group (name, description) VALUES
    ('engineering', 'Engineering department'),
    ('finance',     'Finance department'),
    ('admins',      'System administrators');

INSERT INTO user_group (username, group_name) VALUES
    ('alice', 'engineering'),
    ('alice', 'admins'),
    ('bob',   'engineering'),
    ('carol', 'finance');
EOSQL
