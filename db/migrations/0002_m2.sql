-- OmniPanel M2 migration: integrated platform tables
-- CDN mappings, relay tunnels, WARP peers, BPB policies

BEGIN;

-- ---------- M2: CDN ----------

CREATE TABLE cdn_mappings (
    id serial PRIMARY KEY,
    domain text NOT NULL UNIQUE,
    origin text NOT NULL,
    provider text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- M2: Relay ----------

CREATE TABLE relay_tunnels (
    id serial PRIMARY KEY,
    source_node text NOT NULL,
    destination text NOT NULL,
    protocol text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- M2: WARP ----------

CREATE TABLE warp_peers (
    id serial PRIMARY KEY,
    peer_id text NOT NULL UNIQUE,
    public_key text NOT NULL,
    endpoint text NOT NULL,
    status text NOT NULL DEFAULT 'configured',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- M2: BPB ----------

CREATE TABLE bpb_policies (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    bandwidth_limit integer NOT NULL,
    priority integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX bpb_node_uq ON bpb_policies(node_id);

COMMIT;
