-- Schema exported from trusted baseline 0022d28; no operational data.
BEGIN TRANSACTION;
CREATE TABLE actions(id INTEGER PRIMARY KEY, ts REAL NOT NULL, case_id TEXT NOT NULL,
    action TEXT NOT NULL, ip TEXT, mode TEXT NOT NULL, result TEXT NOT NULL, approved_by TEXT, rejected_by TEXT, action_type TEXT NOT NULL DEFAULT 'block_ip', completed_at REAL, lease_until REAL, actor TEXT, requested_by TEXT, evidence TEXT, verification_status TEXT NOT NULL DEFAULT 'not_verified', run_id TEXT);
CREATE TABLE audit(id INTEGER PRIMARY KEY,ts REAL NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,result TEXT NOT NULL);
CREATE TABLE cases(id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL,
    incident TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT '{}', restore TEXT NOT NULL DEFAULT '{}', provenance TEXT NOT NULL DEFAULT 'legacy_unknown', workflow_status TEXT NOT NULL DEFAULT 'open', latest_run_id TEXT, synthetic INTEGER NOT NULL DEFAULT 0);
CREATE TABLE inbox(id TEXT PRIMARY KEY, received REAL NOT NULL, alert TEXT NOT NULL,
                                case_id TEXT, provenance TEXT NOT NULL DEFAULT 'legacy_unknown', source TEXT NOT NULL DEFAULT 'wazuh', external_id TEXT, normalized TEXT, severity TEXT, event_type TEXT, synthetic INTEGER NOT NULL DEFAULT 0, correlation_status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE incident_alerts(case_id TEXT NOT NULL,alert_id TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(case_id,alert_id));
CREATE TABLE jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,run_id TEXT NOT NULL UNIQUE,case_id TEXT NOT NULL,
 status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,max_attempts INTEGER NOT NULL DEFAULT 3,
 available REAL NOT NULL,created REAL NOT NULL,owner TEXT,lease_until REAL,error TEXT);
CREATE TABLE ledger(id INTEGER PRIMARY KEY, ts REAL NOT NULL, case_id TEXT NOT NULL,
    agent TEXT NOT NULL, mode TEXT NOT NULL, prompt TEXT NOT NULL, response TEXT, evidence TEXT NOT NULL,
    usage TEXT NOT NULL, duration_ms REAL NOT NULL, error TEXT, parameters TEXT, model_source TEXT, run_id TEXT, step_id TEXT, provider TEXT, model TEXT, prompt_version TEXT, attempt INTEGER, tool_name TEXT);
CREATE TABLE notes(id INTEGER PRIMARY KEY,case_id TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,body TEXT NOT NULL);
CREATE TABLE runs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,created REAL NOT NULL,finished REAL,status TEXT NOT NULL,
 evidence TEXT NOT NULL,cutoff REAL NOT NULL,prompt_version TEXT NOT NULL,provider TEXT,model TEXT,mode TEXT NOT NULL,
 replay INTEGER NOT NULL DEFAULT 0,parent_run_id TEXT,verdict TEXT,error TEXT,requested_by TEXT NOT NULL,parameters TEXT);
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied REAL NOT NULL);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE shuffle_outbox(id TEXT PRIMARY KEY,action_id INTEGER NOT NULL UNIQUE,case_id TEXT NOT NULL,
 payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,
 available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT,delivered REAL);
CREATE TABLE steps(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,role TEXT NOT NULL,status TEXT NOT NULL,attempt INTEGER NOT NULL,started REAL,finished REAL,error TEXT);
CREATE TABLE thehive_sync(case_id TEXT PRIMARY KEY,remote_id TEXT,payload_hash TEXT,
 state TEXT NOT NULL DEFAULT 'pending',available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT);
CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,created REAL NOT NULL,disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE vt_budget(id INTEGER PRIMARY KEY CHECK(id=1),day TEXT NOT NULL,count INTEGER NOT NULL,next_at REAL NOT NULL);
CREATE TABLE vt_cache(ip TEXT PRIMARY KEY,report TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE vt_jobs(case_id TEXT NOT NULL,ip TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 available REAL NOT NULL DEFAULT 0,lease_until REAL NOT NULL DEFAULT 0,error TEXT,report TEXT,
 PRIMARY KEY(case_id,ip));
CREATE TABLE workers(id TEXT PRIMARY KEY,last_seen REAL NOT NULL,current_job TEXT);
CREATE INDEX inbox_pending ON inbox(case_id, received);
CREATE INDEX thehive_due ON thehive_sync(available,lease_until);
CREATE INDEX shuffle_due ON shuffle_outbox(status,available,lease_until);
CREATE INDEX vt_due ON vt_jobs(status,available,lease_until);
CREATE INDEX jobs_available ON jobs(status,available);
CREATE UNIQUE INDEX inbox_source_id ON inbox(source,external_id);
CREATE INDEX inbox_filters ON inbox(received,severity,event_type);
COMMIT;
