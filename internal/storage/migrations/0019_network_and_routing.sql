-- SPDX-License-Identifier: AGPL-3.0-only
-- Track 05：双端 IPv4/IPv6 多地址选择与中国客户端分流规则持久化表。

CREATE TABLE node_network_policies (
    node_id                 TEXT PRIMARY KEY,
    inbound_family_mode     TEXT NOT NULL DEFAULT 'prefer_ipv4'
                            CHECK (inbound_family_mode IN ('ipv4_only', 'ipv6_only', 'prefer_ipv4', 'prefer_ipv6')),
    inbound_candidates_json TEXT NOT NULL DEFAULT '[]',
    outbound_family_mode    TEXT NOT NULL DEFAULT 'prefer_ipv4'
                            CHECK (outbound_family_mode IN ('ipv4_only', 'ipv6_only', 'prefer_ipv4', 'prefer_ipv6')),
    outbound_bind_ipv4      TEXT NOT NULL DEFAULT '',
    outbound_bind_ipv6      TEXT NOT NULL DEFAULT '',
    outbound_overrides_json TEXT NOT NULL DEFAULT '[]',
    revision                TEXT NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;

CREATE TABLE client_routing_profiles (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    mode                    TEXT NOT NULL DEFAULT 'rule_cn_split'
                            CHECK (mode IN ('rule_cn_split', 'global_proxy', 'direct_all')),
    block_ads               INTEGER NOT NULL DEFAULT 1 CHECK (block_ads IN (0, 1)),
    dns_anti_poison         INTEGER NOT NULL DEFAULT 1 CHECK (dns_anti_poison IN (0, 1)),
    bundle_version          TEXT NOT NULL DEFAULT 'builtin-minimal',
    bundle_sha256           TEXT NOT NULL DEFAULT '',
    custom_rules_json       TEXT NOT NULL DEFAULT '[]',
    revision                TEXT NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;
