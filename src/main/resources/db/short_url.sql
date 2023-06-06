create table short_url (
    id INTEGER PRIMARY KEY,
    url_key varchar (8) UNIQUE NOT NULL,
    full_url text NOT NULL,
    created_at timestamp without time zone default (now() at time zone 'utc') NOT NULL);

CREATE INDEX idx_short_url_url_key ON short_url (url_key);