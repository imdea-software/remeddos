CREATE USER postgres  WITH PASSWORD 'heix6ieG';
ALTER USER postgres WITH SUPERUSER;
GRANT ALL ON DATABASE flowspy TO postgres;
GRANT ALL ON DATABASE flowspy TO fod;
