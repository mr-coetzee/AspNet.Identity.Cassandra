// Users, keyed by user id
CREATE TABLE IF NOT EXISTS users (
    id uuid,
    username text,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email text,
    email_confirmed boolean,
    PRIMARY KEY (id)
);

// Users, keyed by username
CREATE TABLE IF NOT EXISTS users_by_username (
    username text,
    id uuid,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email text,
    email_confirmed boolean,
    PRIMARY KEY (username)
);

// Users, keyed by email address
CREATE TABLE IF NOT EXISTS users_by_email (
    email text,
    id uuid,
    username text,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email_confirmed boolean,
    PRIMARY KEY (email)
);

// Logins, keyed by user id
CREATE TABLE IF NOT EXISTS logins (
    id uuid,
    login_provider text,
    provider_key text,
    PRIMARY KEY(id, login_provider, provider_key)
);

// Logins, keyed by provider and provider key
CREATE TABLE IF NOT EXISTS logins_by_provider (
    login_provider text,
    provider_key text,
    id uuid,
    PRIMARY KEY ((login_provider, provider_key))
);

// Claims, keyed by user id
CREATE TABLE IF NOT EXISTS claims (
    id uuid,
    type text,
    value text,
    PRIMARY KEY (id, type, value)
);

CREATE TABLE IF NOT EXISTS roles (
    id uuid,
    name text,
    description text,
    PRIMARY KEY (id)
);

// Roles, keyed by name
CREATE TABLE IF NOT EXISTS roles_by_name (
    name text,
    id uuid,
    description text,
    PRIMARY KEY (name)
);
