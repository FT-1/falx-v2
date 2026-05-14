-- =============================================================================
-- Project: FALX V2
-- Lead Architect & Owner: FT-1
-- Description: Default policy rules seed (configs/default_policy_rules.sql).
--              Applied on first startup if the policy DB is empty.
--              Rules are ordered by priority (higher = evaluated first).
--              Run: sqlite3 /var/lib/falx/policy.db < default_policy_rules.sql
-- =============================================================================

-- ─── Tier 1 (Priority 9000-10000): Critical Infrastructure Allowlist ─────────
-- These rules must fire BEFORE any block rules to protect legitimate services.

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_001',
    'Allow-Loopback',
    'Always allow loopback traffic',
    9999, 1, 'allow',
    '[{"type":"src_ip","operator":"cidr","value":"127.0.0.0/8"}]',
    'AND', 0, 0, 'loopback_allow', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_002',
    'Allow-RFC1918-Admin',
    'Allow management traffic from internal networks',
    9500, 1, 'allow',
    '[{"type":"src_ip","operator":"cidr","value":"10.0.0.0/8"},
      {"type":"dst_port","operator":"range","value":"1-1024"}]',
    'AND', 0, 0, 'internal_admin', 'system', datetime('now'), datetime('now')
);

-- ─── Tier 2 (Priority 5000-8999): Threat Detection & Blocking ────────────────

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_010',
    'Block-HighThreatScore',
    'Block any IP with AI threat score >= 90 (high confidence threat)',
    8000, 1, 'block',
    '[{"type":"threat_score","operator":"gte","value":"90"}]',
    'AND', 3600, 1, 'high_threat_score', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_011',
    'Alert-MediumThreatScore',
    'Alert (no block) for IPs with threat score 60-89',
    7500, 1, 'alert',
    '[{"type":"threat_score","operator":"gte","value":"60"},
      {"type":"threat_score","operator":"lt","value":"90"}]',
    'AND', 0, 0, 'medium_threat_score', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_020',
    'Block-BruteForcePorts',
    'Rate-limit IPs accessing brute-force targets (SSH/RDP/VNC)',
    7000, 1, 'rate_limit',
    '[{"type":"dst_port","operator":"in","value":"22,23,3389,5900"}]',
    'AND', 300, 2, 'brute_force_port', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_030',
    'Block-KnownBadCIDRs',
    'Block traffic from well-known malicious IP ranges',
    6500, 0,  -- Disabled by default; enable after validating against your network
    'block',
    '[{"type":"src_ip","operator":"cidr","value":"0.0.0.0/8"},
      {"type":"src_ip","operator":"cidr","value":"100.64.0.0/10"},
      {"type":"src_ip","operator":"cidr","value":"169.254.0.0/16"}]',
    'OR', 86400, 3, 'bogon_cidrs', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_040',
    'Honeypot-Scanners',
    'Redirect port scanners (sequential port access) to honeypot',
    6000, 1, 'redirect',
    '[{"type":"threat_score","operator":"gte","value":"70"},
      {"type":"dst_port","operator":"gt","value":"1024"}]',
    'AND', 1800, 4, 'port_scan_honeypot', 'system', datetime('now'), datetime('now')
);

-- ─── Tier 3 (Priority 1000-4999): Monitoring & Alerts ────────────────────────

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_050',
    'Alert-DNS-Amplification',
    'Alert on potential DNS amplification attack sources',
    4000, 1, 'alert',
    '[{"type":"dst_port","operator":"eq","value":"53"},
      {"type":"threat_score","operator":"gte","value":"40"}]',
    'AND', 0, 5, 'dns_amplification', 'system', datetime('now'), datetime('now')
);

INSERT OR IGNORE INTO rules
(id, name, description, priority, enabled, action,
 conditions, cond_logic, ttl_s, rule_id, reason, created_by, created_at, updated_at)
VALUES (
    'rule_default_060',
    'Alert-ICMP-Flood',
    'Alert on ICMP traffic with high packet rates (protocol=1)',
    3500, 1, 'alert',
    '[{"type":"protocol","operator":"eq","value":"1"},
      {"type":"threat_score","operator":"gte","value":"50"}]',
    'AND', 0, 6, 'icmp_flood', 'system', datetime('now'), datetime('now')
);
