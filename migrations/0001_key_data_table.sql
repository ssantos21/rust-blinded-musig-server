CREATE TABLE public.key_data (
	id serial4 NOT NULL,
	sealed_secret_key bytea NULL,
	sealed_secnonce bytea NULL,
	public_nonce bytea NULL,
	public_key bytea NULL,
	CONSTRAINT key_data_pkey PRIMARY KEY (id),
	CONSTRAINT key_data_public_key_key UNIQUE (public_key)
);