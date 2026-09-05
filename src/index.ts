import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import initSqlJs from "sql.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { generateKeyPairSync, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// ============================================================
// Bot Lock MCP Server v1.0.0
// Identity & Security for AI Agents
// By AgentHive Inc. | BUSL-1.1
// ============================================================

const DATA_DIR = join(homedir(), ".clawlock");
const DB_PATH = join(DATA_DIR, "clawlock.db");
const KEY_PATH = join(DATA_DIR, ".master_key");
const VERSION = "1.0.0";
const TRIAL_MS = 48 * 60 * 60 * 1000;

const TIERS: Record<string, { maxAgents: number; autoRotation: boolean }> = {
  trial:      { maxAgents: 2,    autoRotation: false },
  starter:    { maxAgents: 5,    autoRotation: false },
  pro:        { maxAgents: 25,   autoRotation: true },
  enterprise: { maxAgents: 9999, autoRotation: true },
};

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

// ---- Encryption ----
function getMasterKey(): Buffer {
  if (existsSync(KEY_PATH)) return Buffer.from(readFileSync(KEY_PATH, "utf-8"), "hex");
  const key = randomBytes(32);
  writeFileSync(KEY_PATH, key.toString("hex"), { mode: 0o600 });
  return key;
}
const MASTER = getMasterKey();

function encrypt(plain: string): string {
  const iv = randomBytes(16);
  const c = createCipheriv("aes-256-gcm", MASTER, iv);
  let enc = c.update(plain, "utf8", "hex"); enc += c.final("hex");
  return `${iv.toString("hex")}:${c.getAuthTag().toString("hex")}:${enc}`;
}
function decrypt(cipher: string): string {
  const [ivH, tagH, enc] = cipher.split(":");
  const d = createDecipheriv("aes-256-gcm", MASTER, Buffer.from(ivH, "hex"));
  d.setAuthTag(Buffer.from(tagH, "hex"));
  let dec = d.update(enc, "hex", "utf8"); dec += d.final("utf8");
  return dec;
}

// ---- DB helpers (sql.js) ----
let db: any;

function saveDb() { writeFileSync(DB_PATH, Buffer.from(db.export())); }

function run(sql: string, params: any[] = []) {
  db.run(sql, params);
  saveDb();
}

function getOne(sql: string, params: any[] = []): any | null {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const row = stmt.getAsObject(); stmt.free(); return row; }
  stmt.free();
  return null;
}

function getAll(sql: string, params: any[] = []): any[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows: any[] = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function logAudit(agentId: string | null, action: string, resource: string | null, details: string | null, result = "allowed") {
  run("INSERT INTO audit_log (id, timestamp, agent_id, action, resource, details, result) VALUES (?,datetime('now'),?,?,?,?,?)",
    [uuidv4(), agentId, action, resource, details, result]);
}

function checkLicense(): { tier: string; limits: typeof TIERS.trial; expired: boolean } {
  const row = getOne("SELECT * FROM license WHERE id = 'main'");
  const tier = row?.tier || "trial";
  const limits = TIERS[tier] || TIERS.trial;
  if (tier === "trial") {
    const expired = Date.now() - new Date(row.activated_at + "Z").getTime() > TRIAL_MS;
    return { tier, limits, expired };
  }
  return { tier, limits, expired: false };
}

function requireLicense(action: string) {
  const { expired } = checkLicense();
  if (expired) {
    logAudit(null, action, null, "Trial expired", "denied");
    throw new Error("Bot Lock trial expired. Upgrade: https://clawlock-security.netlify.app/#pricing");
  }
}

// ============================================================
// Server
// ============================================================
const server = new McpServer({ name: "clawlock-mcp-server", version: VERSION });

// ---- IDENTITY ----
server.registerTool("clawlock_register_agent", {
  title: "Register Agent", description: "Create agent with Ed25519 identity and scopes.",
  inputSchema: { name: z.string(), scopes: z.array(z.string()).optional() },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
}, async ({ name, scopes }) => {
  requireLicense("register_agent");
  const { limits } = checkLicense();
  const cnt = getOne("SELECT COUNT(*) as c FROM agents WHERE status='active'");
  if ((cnt?.c || 0) >= limits.maxAgents) throw new Error(`Agent limit (${limits.maxAgents}). Upgrade: https://clawlock-security.netlify.app/#pricing`);
  const id = `ag_${uuidv4().split("-")[0]}`;
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }) as string;
  const priv = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  run("INSERT INTO agents (id,name,public_key,private_key_encrypted,scopes,status,created_at,updated_at) VALUES (?,?,?,?,?,'active',datetime('now'),datetime('now'))",
    [id, name, pub, encrypt(priv), JSON.stringify(scopes || [])]);
  logAudit(id, "register_agent", null, `Registered: ${name}`);
  return { content: [{ type: "text", text: JSON.stringify({ id, name, status: "active", scopes: scopes || [] }, null, 2) }] };
});

server.registerTool("clawlock_get_agent", {
  title: "Get Agent", description: "Get agent details by ID.",
  inputSchema: { agent_id: z.string() }, annotations: { readOnlyHint: true },
}, async ({ agent_id }) => {
  requireLicense("get_agent");
  const row = getOne("SELECT id,name,public_key,scopes,status,created_at,updated_at FROM agents WHERE id=?", [agent_id]);
  if (!row) throw new Error(`Agent not found: ${agent_id}`);
  row.scopes = JSON.parse(row.scopes);
  return { content: [{ type: "text", text: JSON.stringify(row, null, 2) }] };
});

server.registerTool("clawlock_list_agents", {
  title: "List Agents", description: "List all registered agents.",
  inputSchema: { status: z.enum(["active","suspended","revoked","all"]).optional() },
  annotations: { readOnlyHint: true },
}, async ({ status }) => {
  requireLicense("list_agents");
  const q = status && status !== "all" ? "SELECT id,name,scopes,status,created_at FROM agents WHERE status=?" : "SELECT id,name,scopes,status,created_at FROM agents";
  const p = status && status !== "all" ? [status] : [];
  const rows = getAll(q, p);
  rows.forEach(r => r.scopes = JSON.parse(r.scopes));
  return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
});

server.registerTool("clawlock_suspend_agent", {
  title: "Suspend Agent", description: "Temporarily suspend an agent.",
  inputSchema: { agent_id: z.string() }, annotations: { readOnlyHint: false },
}, async ({ agent_id }) => {
  requireLicense("suspend_agent");
  run("UPDATE agents SET status='suspended',updated_at=datetime('now') WHERE id=?", [agent_id]);
  logAudit(agent_id, "suspend_agent", null, "Suspended");
  return { content: [{ type: "text", text: `Agent ${agent_id} suspended.` }] };
});

server.registerTool("clawlock_revoke_agent", {
  title: "Revoke Agent", description: "Permanently revoke agent and all credentials.",
  inputSchema: { agent_id: z.string() }, annotations: { readOnlyHint: false, destructiveHint: true },
}, async ({ agent_id }) => {
  requireLicense("revoke_agent");
  run("UPDATE agents SET status='revoked',updated_at=datetime('now') WHERE id=?", [agent_id]);
  run("UPDATE credentials SET status='revoked' WHERE agent_id=?", [agent_id]);
  logAudit(agent_id, "revoke_agent", null, "Agent + credentials revoked");
  return { content: [{ type: "text", text: `Agent ${agent_id} permanently revoked.` }] };
});

server.registerTool("clawlock_check_scope", {
  title: "Check Scope", description: "Check if agent has a specific permission scope.",
  inputSchema: { agent_id: z.string(), scope: z.string() }, annotations: { readOnlyHint: true },
}, async ({ agent_id, scope }) => {
  requireLicense("check_scope");
  const row = getOne("SELECT scopes,status FROM agents WHERE id=?", [agent_id]);
  if (!row) throw new Error(`Agent not found: ${agent_id}`);
  if (row.status !== "active") {
    logAudit(agent_id, "check_scope", scope, `Agent ${row.status}`, "denied");
    return { content: [{ type: "text", text: JSON.stringify({ allowed: false, reason: `Agent is ${row.status}` }) }] };
  }
  const scopes = JSON.parse(row.scopes) as string[];
  const allowed = scopes.includes(scope) || scopes.includes("*");
  logAudit(agent_id, "check_scope", scope, null, allowed ? "allowed" : "denied");
  return { content: [{ type: "text", text: JSON.stringify({ allowed, agent_id, scope }) }] };
});

// ---- VAULT ----
server.registerTool("clawlock_store_credential", {
  title: "Store Credential", description: "Store API key in encrypted vault scoped to an agent.",
  inputSchema: {
    agent_id: z.string(), service: z.string(), key: z.string(),
    label: z.string().optional(), rotation_interval_hours: z.number().optional(),
  },
  annotations: { readOnlyHint: false },
}, async ({ agent_id, service, key, label, rotation_interval_hours }) => {
  requireLicense("store_credential");
  const agent = getOne("SELECT status FROM agents WHERE id=?", [agent_id]);
  if (!agent || agent.status !== "active") throw new Error(`Agent ${agent_id} not found or inactive`);
  if (rotation_interval_hours && !checkLicense().limits.autoRotation)
    throw new Error("Auto-rotation requires Pro+. Upgrade: https://clawlock-security.netlify.app/#pricing");
  const id = `cred_${uuidv4().split("-")[0]}`;
  run("INSERT INTO credentials (id,agent_id,service,key_encrypted,label,rotation_interval_hours,status,created_at) VALUES (?,?,?,?,?,?,'active',datetime('now'))",
    [id, agent_id, service, encrypt(key), label || null, rotation_interval_hours || null]);
  logAudit(agent_id, "store_credential", service, `Stored: ${id}`);
  return { content: [{ type: "text", text: JSON.stringify({ id, agent_id, service, label, encrypted: true }) }] };
});

server.registerTool("clawlock_use_credential", {
  title: "Use Credential", description: "Decrypt and retrieve a credential. Logged to audit.",
  inputSchema: { agent_id: z.string(), credential_id: z.string() },
  annotations: { readOnlyHint: true },
}, async ({ agent_id, credential_id }) => {
  requireLicense("use_credential");
  const cred = getOne("SELECT * FROM credentials WHERE id=? AND agent_id=? AND status='active'", [credential_id, agent_id]);
  if (!cred) { logAudit(agent_id, "use_credential", credential_id, "Not found/unauthorized", "denied"); throw new Error("Credential not found or unauthorized"); }
  const key = decrypt(cred.key_encrypted);
  logAudit(agent_id, "use_credential", cred.service, `Accessed: ${credential_id}`);
  return { content: [{ type: "text", text: JSON.stringify({ credential_id, service: cred.service, key }) }] };
});

server.registerTool("clawlock_list_credentials", {
  title: "List Credentials", description: "List credential metadata for an agent (keys NOT returned).",
  inputSchema: { agent_id: z.string() }, annotations: { readOnlyHint: true },
}, async ({ agent_id }) => {
  requireLicense("list_credentials");
  const rows = getAll("SELECT id,service,label,status,rotation_interval_hours,created_at FROM credentials WHERE agent_id=?", [agent_id]);
  return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
});

server.registerTool("clawlock_revoke_credential", {
  title: "Revoke Credential", description: "Permanently revoke a credential.",
  inputSchema: { agent_id: z.string(), credential_id: z.string() },
  annotations: { readOnlyHint: false, destructiveHint: true },
}, async ({ agent_id, credential_id }) => {
  requireLicense("revoke_credential");
  run("UPDATE credentials SET status='revoked' WHERE id=? AND agent_id=?", [credential_id, agent_id]);
  logAudit(agent_id, "revoke_credential", credential_id, "Revoked");
  return { content: [{ type: "text", text: `Credential ${credential_id} revoked.` }] };
});

// ---- AUDIT ----
server.registerTool("clawlock_get_audit_log", {
  title: "Get Audit Log", description: "Query the immutable audit ledger.",
  inputSchema: {
    agent_id: z.string().optional(), action: z.string().optional(),
    limit: z.number().optional(), offset: z.number().optional(),
  },
  annotations: { readOnlyHint: true },
}, async ({ agent_id, action, limit, offset }) => {
  requireLicense("get_audit_log");
  let q = "SELECT * FROM audit_log";
  const conds: string[] = []; const p: any[] = [];
  if (agent_id) { conds.push("agent_id=?"); p.push(agent_id); }
  if (action) { conds.push("action LIKE ?"); p.push(`%${action}%`); }
  if (conds.length) q += " WHERE " + conds.join(" AND ");
  q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
  p.push(limit || 50, offset || 0);
  const rows = getAll(q, p);
  return { content: [{ type: "text", text: JSON.stringify({ entries: rows, count: rows.length }, null, 2) }] };
});

// ---- LICENSE ----
server.registerTool("clawlock_get_status", {
  title: "Get Status", description: "Check license tier, usage, and system status.",
  inputSchema: {}, annotations: { readOnlyHint: true },
}, async () => {
  const { tier, limits, expired } = checkLicense();
  const agents = getOne("SELECT COUNT(*) as c FROM agents WHERE status='active'")?.c || 0;
  const creds = getOne("SELECT COUNT(*) as c FROM credentials WHERE status='active'")?.c || 0;
  const audits = getOne("SELECT COUNT(*) as c FROM audit_log")?.c || 0;
  return { content: [{ type: "text", text: JSON.stringify({
    version: VERSION, tier, expired, limits, usage: { agents, credentials: creds, auditEntries: audits },
    upgradeUrl: "https://clawlock-security.netlify.app/#pricing"
  }, null, 2) }] };
});

server.registerTool("clawlock_activate_license", {
  title: "Activate License", description: "Activate a paid license key.",
  inputSchema: { license_key: z.string(), tier: z.enum(["starter","pro","enterprise"]) },
  annotations: { readOnlyHint: false },
}, async ({ license_key, tier }) => {
  run("UPDATE license SET tier=?,license_key=?,activated_at=datetime('now') WHERE id='main'", [tier, license_key]);
  logAudit(null, "activate_license", null, `Activated: ${tier}`);
  return { content: [{ type: "text", text: `License activated: ${tier}. Max agents: ${TIERS[tier].maxAgents}. Lock your bots.` }] };
});

// ============================================================
// Main
// ============================================================
async function main() {
  const SQL = await initSqlJs();
  if (existsSync(DB_PATH)) {
    const buf = readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS license (id TEXT PRIMARY KEY DEFAULT 'main', tier TEXT NOT NULL DEFAULT 'trial', activated_at TEXT NOT NULL DEFAULT (datetime('now')), license_key TEXT, stripe_customer_id TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL, private_key_encrypted TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, service TEXT NOT NULL, key_encrypted TEXT NOT NULL, label TEXT, rotation_interval_hours INTEGER, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT (datetime('now')), agent_id TEXT, action TEXT NOT NULL, resource TEXT, details TEXT, result TEXT NOT NULL DEFAULT 'allowed')`);

  const lic = getOne("SELECT * FROM license WHERE id='main'");
  if (!lic) run("INSERT INTO license (id,tier) VALUES ('main','trial')");

  saveDb();

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Bot Lock MCP Server v${VERSION} running (stdio)`);
}

main().catch(e => { console.error("Fatal:", e); process.exit(1); });