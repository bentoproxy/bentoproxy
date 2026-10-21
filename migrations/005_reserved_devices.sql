-- Reserved nodes carry only traffic that names them (proxy username
-- api-node-<device_id>), never the general pool. For a node whose exit should
-- be kept for one site, e.g. a VPN address one portal accepts and others
-- would flag.
ALTER TABLE devices ADD COLUMN reserved INTEGER NOT NULL DEFAULT 0;
