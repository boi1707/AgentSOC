"""Durable managed responses. Only dependency-injected simulation is available."""

import errno
import json
import logging
import math
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import auth, response
from .response_adapters import (
    PFSENSE_ALIAS,
    ManagedTransport,
    PermanentMutation,
    PfSenseAdapter,
    RetryableMutation,
    UnknownMutation,
)

MODE = "managed-simulation"
CLAIM_SECONDS = 30
MAX_ATTEMPTS = 5
# Also fence older outbox workers that do not recognize the local_only status.
LOCAL_ONLY_AVAILABLE = float("inf")
log = logging.getLogger("agentsoc.managed_response")


class ClaimLost(Exception):
    """The worker no longer owns a current claim."""


class UnsafeObservation(Exception):
    """A transport observed an unexpected alias identity or change."""


@contextmanager
def exclusive_worker(database):
    """Coordinate workers using the same local DB, including during transport calls."""
    path = Path(database).resolve()
    with path.with_name(path.name + ".managed.lock").open("a+b") as lock:
        try:
            if os.name == "nt":
                import msvcrt

                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            yield False
        else:
            # Closing this descriptor releases the lock even after process failure.
            yield True


class ManagedResponse:
    def __init__(self, store, settings, transport: ManagedTransport, *, clock=time.time, enabled=True):
        self.store = store
        self.settings = settings
        self.transport = transport
        self.identity = transport.identity
        self.clock = clock
        self.enabled = enabled

    @property
    def accepting(self):
        return self.enabled and not self.settings.demo and self.settings.response_mode == "dry-run"

    @staticmethod
    def authorized(db, actor):
        row = db.execute("SELECT role FROM users WHERE username=? AND disabled=0", (actor,)).fetchone()
        return bool(row and auth.ROLES.get(row["role"], -1) >= auth.ROLES["approver"])

    def validate_evidence(self, db, case, run, ip):
        verdict = case["verdict"]
        if (
            self.settings.demo
            or case["synthetic"]
            or case["provenance"] != "received"
            or not run
            or run["case_id"] != case["id"]
            or run["mode"] != "live"
            or verdict.get("mode") != "live"
            or not math.isfinite(verdict.get("confidence", 0))
            or not run["finished"]
        ):
            raise ValueError("Managed response requires trusted live evidence")
        PfSenseAdapter(self.settings).validate_target(ip)
        run_verdict = json.loads(run["verdict"]) if isinstance(run["verdict"], str) else run["verdict"]
        if run_verdict != verdict:
            raise ValueError("Managed response verdict must match the approved run")
        evidence = json.loads(run["evidence"]) if isinstance(run["evidence"], str) else run["evidence"]
        cited = set(verdict["evidence_ids"])
        source_ids = {
            alert["id"]
            for alert in evidence["alerts"]
            if alert["id"] in cited and alert["kind"] == "net" and alert.get("src_ip") == ip
        }
        trusted = set()
        for row in db.execute(
            """SELECT i.id,i.normalized FROM incident_alerts l JOIN inbox i ON i.id=l.alert_id
               WHERE l.case_id=? AND i.source=? AND i.provenance='received' AND i.synthetic=0""",
            (case["id"], self.settings.wazuh_source),
        ):
            normalized = json.loads(row["normalized"])
            trusted.add(row["id"])
            if row["id"] in source_ids:
                if normalized["evidence"].get("kind") != "net" or normalized["evidence"].get("src_ip") != ip:
                    raise ValueError("Managed response source does not match the original alert")
        if not source_ids.intersection(trusted) or not cited.issubset(trusted):
            raise ValueError("Managed response requires original cited alerts")

    def still_eligible(self, db, lease):
        case_row = db.execute("SELECT * FROM cases WHERE id=?", (lease["case_id"],)).fetchone()
        run = db.execute("SELECT * FROM runs WHERE id=?", (lease["run_id"],)).fetchone()
        if (
            not case_row
            or not run
            or run["status"] != "completed"
            or run["replay"]
            or not run["finished"]
            or self.clock() >= run["finished"] + self.settings.proposal_ttl
            or case_row["workflow_status"] == "closed"
            or case_row["latest_run_id"] != lease["run_id"]
            or not self.authorized(db, lease["approved_by"])
        ):
            return False
        case = self.store.decode(case_row)
        try:
            ip = response.candidate(case, self.settings)
            self.validate_evidence(db, case, run, ip)
        except (ValueError, KeyError, TypeError, AttributeError):
            return False
        return ip == lease["source_ip"]

    def queue(self, db, case, run, action_id, ip, actor, now):
        activation_deadline = min(now + 300, run["finished"] + self.settings.proposal_ttl)
        db.execute(
            """INSERT INTO managed_block_leases(
                  id,proposal_id,run_id,case_id,action_id,firewall_identity,alias_identity,source_ip,
                  approved_by,created_at,desired_state,next_retry_at,activation_deadline,block_ttl_seconds
               ) VALUES(?,?,?,?,?,?,?,?,?,?,'present',?,?,?)""",
            (
                uuid.uuid4().hex,
                run["id"],
                run["id"],
                case["id"],
                action_id,
                self.identity,
                PFSENSE_ALIAS,
                ip,
                actor,
                now,
                now,
                activation_deadline,
                self.settings.pfsense_block_ttl,
            ),
        )

    def tick(self):
        """Process one response independently of potentially long analysis cycles."""
        with exclusive_worker(self.store.path) as acquired:
            if not acquired:
                return False
            lease = self.claim()
            if not lease:
                return False
            try:
                self.process(lease)
            except ClaimLost:
                log.info("managed.claim_lost", extra={"case_id": lease["case_id"]})
            return True

    def process(self, lease):
        try:
            if lease["desired_state"] == "present":
                self.activate(lease)
            else:
                self.remove(lease)
        except UnsafeObservation:
            self.failure(lease, "unexpected_firewall_state", permanent=True)
        except PermanentMutation:
            self.failure(lease, "permanent_failure", permanent=True)
        except RetryableMutation:
            self.failure(lease, "retryable_failure")
        except (UnknownMutation, TimeoutError):
            self.failure(lease, "action_unknown")

    @staticmethod
    def activation_limit(lease):
        limit = lease["activation_deadline"]
        ttl = lease["block_ttl_seconds"]
        if limit is None or not ttl:
            return lease["created_at"]
        started = lease["block_requested_at"]
        return limit if started is None else min(limit, started + ttl)

    def observe(self, lease):
        self.check_identity(lease)
        observed = self.transport.observe(lease["source_ip"])
        if (
            observed.alias_identity != lease["alias_identity"]
            or observed.unexpected_changes
            or (not observed.applied and observed.pending_owner != lease["ownership_marker"])
            or (not observed.applied and observed.pending_owner is None)
        ):
            raise UnsafeObservation
        return observed

    def check_identity(self, lease):
        if self.transport.identity != lease["firewall_identity"]:
            raise UnsafeObservation

    @contextmanager
    def owned_transaction(self, lease):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                """SELECT 1 FROM managed_block_leases WHERE id=? AND execution_owner=?
                   AND execution_lease_until>?""",
                (lease["id"], lease["execution_owner"], self.clock()),
            ).fetchone():
                raise ClaimLost
            yield db

    def claim(self):
        now = self.clock()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT l.*,a.result FROM managed_block_leases l JOIN actions a ON a.id=l.action_id
                   WHERE l.firewall_identity=:identity AND l.alias_identity=:alias AND a.mode=:mode
                     AND (l.execution_lease_until IS NULL OR l.execution_lease_until<=:now)
                     AND l.next_retry_at>=0 AND (
                         (l.desired_state='absent' AND l.next_retry_at<=:now)
                         OR (l.desired_state='present' AND l.activated_at IS NULL AND
                             (l.next_retry_at<=:now OR l.activation_deadline<=:now OR :disabled
                              OR l.block_requested_at+l.block_ttl_seconds<=:now))
                         OR (l.desired_state='present' AND l.activated_at IS NOT NULL AND
                             (l.expires_at<=:now OR l.block_requested_at+l.block_ttl_seconds<=:now))
                     )
                   ORDER BY CASE WHEN l.desired_state='absent' OR l.expires_at<=:now
                                      OR l.block_requested_at+l.block_ttl_seconds<=:now THEN 0 ELSE 1 END,
                            l.next_retry_at,l.created_at,l.id LIMIT 1""",
                {
                    "identity": self.identity,
                    "alias": PFSENSE_ALIAS,
                    "mode": MODE,
                    "now": now,
                    "disabled": not self.accepting,
                },
            ).fetchone()
            if not row:
                return None
            lease = dict(row)
            if lease["execution_owner"]:
                lease["attempts"] += 1
            if lease["desired_state"] == "present":
                if lease["activated_at"] is not None:
                    self.start_cleanup(db, lease, now, expired=True)
                elif not self.accepting or now >= self.activation_limit(lease):
                    self.stop_activation(
                        db, lease, now, "execution_disabled" if not self.accepting else "activation_expired"
                    )
                elif not self.still_eligible(db, lease):
                    self.stop_activation(db, lease, now, "eligibility_changed")
                elif lease["attempts"] >= MAX_ATTEMPTS:
                    self.stop_activation(db, lease, now, "action_unknown")
                else:
                    self.stage(db, lease, "executing")
            if lease["desired_state"] == "absent" and lease["attempts"] >= MAX_ATTEMPTS:
                lease["read_only_reconciliation"] = True
            lease["execution_owner"] = uuid.uuid4().hex
            lease["execution_lease_until"] = now + CLAIM_SECONDS
            db.execute(
                "UPDATE managed_block_leases SET execution_owner=?,execution_lease_until=?,attempts=? WHERE id=?",
                (lease["execution_owner"], lease["execution_lease_until"], lease["attempts"], lease["id"]),
            )
            self.store.audit(
                "managed-worker", "response.managed.claim", lease["case_id"], lease["desired_state"], db=db
            )
            return lease

    def stage(self, db, lease, status, verification="not_verified", *, completed_at=None):
        db.execute(
            "UPDATE actions SET result=?,verification_status=?,completed_at=COALESCE(?,completed_at) WHERE id=?",
            (status, verification, completed_at, lease["action_id"]),
        )
        db.execute(
            "UPDATE cases SET status=? WHERE id=? AND latest_run_id=?",
            (status, lease["case_id"], lease["run_id"]),
        )
        self.store.audit("managed-worker", "response.managed", lease["case_id"], status, db=db)

    def start_cleanup(self, db, lease, now, *, expired=False):
        db.execute(
            """UPDATE managed_block_leases SET desired_state='absent',attempts=0,next_retry_at=?
               WHERE id=?""",
            (now, lease["id"]),
        )
        lease.update(desired_state="absent", attempts=0)
        if expired:
            self.lifecycle_event(db, lease, "response.expired", "unblock_pending", now)
        self.stage(db, lease, "unblock_pending")

    def stop_activation(self, db, lease, now, reason):
        status = "action_unknown" if lease["ownership_marker"] else "block_failed"
        self.stage(db, lease, status, completed_at=now)
        self.store.audit("managed-worker", "response.activation_cancelled", lease["case_id"], reason, db=db)
        self.completed_event(db, lease)
        db.execute("UPDATE managed_block_leases SET last_error=? WHERE id=?", (reason, lease["id"]))
        if lease["ownership_marker"]:
            self.start_cleanup(db, lease, now)
        else:
            lease["desired_state"] = "absent"
            db.execute(
                """UPDATE managed_block_leases SET desired_state='absent', next_retry_at=-1
                   WHERE id=?""",
                (lease["id"],),
            )
            lease["skip_cleanup"] = True

    def activate(self, lease):
        ip = lease["source_ip"]
        deadline = min(self.activation_limit(lease), lease["execution_lease_until"])
        self.check_activation(lease, deadline)
        observed = self.observe(lease)
        self.check_deadline(deadline)
        marker = lease["ownership_marker"]
        if self.clean_absent(observed):
            marker = marker or lease["id"]
            with self.owned_transaction(lease) as db:
                self.check_activation(lease, deadline, db=db)
                if lease["block_requested_at"] is None:
                    lease["block_requested_at"] = self.clock()
                db.execute(
                    "UPDATE managed_block_leases SET ownership_marker=?,block_requested_at=? WHERE id=?",
                    (marker, lease["block_requested_at"], lease["id"]),
                )
                lease["ownership_marker"] = marker
            deadline = min(self.activation_limit(lease), lease["execution_lease_until"])
            self.check_activation(lease, deadline)
            self.transport.configure(ip, revision=observed.revision, owner=marker, deadline=deadline)
            observed = self.observe(lease)
        if marker and observed.configured and observed.configured_owner == marker:
            with self.owned_transaction(lease) as db:
                self.stage(db, lease, "configured")
            if not observed.applied:
                if observed.pending_owner != marker:
                    raise UnknownMutation
                self.check_activation(lease, deadline)
                self.transport.apply(ip, revision=observed.revision, deadline=deadline)
                observed = self.observe(lease)
            if observed.applied and observed.configured and observed.configured_owner == marker:
                with self.owned_transaction(lease) as db:
                    self.stage(db, lease, "applied")
        if not self.clean_present(observed):
            raise UnknownMutation
        owner = observed.configured_owner
        with self.owned_transaction(lease) as db:
            self.check_activation(lease, deadline, db=db)
            now = self.clock()
            if now >= deadline:
                raise UnknownMutation
            if owner and owner != marker and not self.active_peer(db, lease, owner, now):
                raise UnknownMutation
            # Retain an earlier possible ownership claim until its absence has been reconciled.
            if marker and owner != marker:
                raise UnknownMutation
            started = lease["block_requested_at"]
            expires = (now if started is None else started) + lease["block_ttl_seconds"]
            db.execute(
                """UPDATE managed_block_leases
                   SET activated_at=?,expires_at=?,next_retry_at=?,observed_state='present',
                       ownership=?,ownership_marker=?,last_verified_at=?,last_error=NULL,attempts=0
                   WHERE id=?""",
                (now, expires, expires, "managed" if owner else "external", owner, now, lease["id"]),
            )
            self.stage(db, lease, "runtime_block_verified", "simulated_runtime_verified", completed_at=now)
            self.completed_event(db, lease)
            self.release(db, lease)

    def remove(self, lease):
        if lease.get("skip_cleanup"):
            with self.owned_transaction(lease) as db:
                self.release(db, lease)
            return
        ip = lease["source_ip"]
        marker = lease["ownership_marker"]
        deadline = lease["execution_lease_until"]
        self.check_cleanup(lease, deadline)
        observed = self.observe(lease)
        with self.owned_transaction(lease) as db:
            if marker and self.active_peer(db, lease, marker, self.clock()):
                if not self.clean_present(observed) or observed.runtime_owner != marker:
                    raise UnknownMutation
                self.finish_cleanup(db, lease, "unblock_retained", "present")
                return
        can_mutate = not lease.get("read_only_reconciliation")
        if can_mutate and marker and observed.configured and observed.configured_owner == marker:
            if observed.runtime_member and observed.runtime_owner != marker:
                raise UnknownMutation
            if not observed.applied and observed.pending_owner != marker:
                raise UnknownMutation
            self.check_cleanup(lease, deadline)
            self.transport.configure(ip, revision=observed.revision, owner=None, deadline=deadline)
            observed = self.observe(lease)
        if (
            can_mutate
            and marker
            and not observed.configured
            and not observed.applied
            and observed.pending_owner == marker
        ):
            if observed.runtime_member and observed.runtime_owner != marker:
                raise UnknownMutation
            self.check_cleanup(lease, deadline)
            self.transport.apply(ip, revision=observed.revision, deadline=deadline)
            observed = self.observe(lease)
        with self.owned_transaction(lease) as db:
            if self.clean_absent(observed):
                self.finish_cleanup(db, lease, "runtime_unblock_verified", "absent")
            elif self.clean_present(observed) and (marker is None or observed.configured_owner != marker):
                self.finish_cleanup(db, lease, "unblock_retained", "present")
            else:
                raise UnknownMutation

    @staticmethod
    def active_peer(db, lease, marker, now):
        return db.execute(
            """SELECT 1 FROM managed_block_leases
               WHERE id<>? AND firewall_identity=? AND alias_identity=? AND source_ip=?
                 AND ownership_marker=? AND ownership='managed' AND desired_state='present' AND expires_at>?
                 AND (block_requested_at IS NULL OR block_requested_at+block_ttl_seconds>?)
               LIMIT 1""",
            (
                lease["id"],
                lease["firewall_identity"],
                lease["alias_identity"],
                lease["source_ip"],
                marker,
                now,
                now,
            ),
        ).fetchone()

    @staticmethod
    def clean_absent(observed):
        return (
            observed.applied
            and not observed.configured
            and not observed.runtime_member
            and observed.configured_owner is None
            and observed.runtime_owner is None
            and observed.pending_owner is None
        )

    @staticmethod
    def clean_present(observed):
        return (
            observed.applied
            and observed.configured
            and observed.runtime_member
            and observed.configured_owner == observed.runtime_owner
            and observed.pending_owner is None
        )

    def check_deadline(self, deadline):
        if self.clock() >= deadline:
            raise UnknownMutation

    def check_activation(self, lease, deadline, *, db=None):
        if db is None:
            with self.owned_transaction(lease) as db:
                self.check_activation(lease, deadline, db=db)
            return
        if not self.accepting or not self.still_eligible(db, lease):
            raise PermanentMutation
        self.check_identity(lease)
        self.check_deadline(deadline)

    def check_cleanup(self, lease, deadline):
        with self.owned_transaction(lease):
            self.check_identity(lease)
            self.check_deadline(deadline)

    def finish_cleanup(self, db, lease, status, observed):
        now = self.clock()
        db.execute(
            """UPDATE managed_block_leases SET observed_state=?,next_retry_at=-1,last_verified_at=?,
               last_error=NULL,attempts=0 WHERE id=?""",
            (observed, now, lease["id"]),
        )
        verification = "simulated_runtime_verified" if observed == "absent" else "not_verified"
        self.stage(db, lease, status, verification, completed_at=now)
        self.lifecycle_event(db, lease, "response.unblock.completed", status, now, verification)
        self.release(db, lease)

    def failure(self, lease, reason, *, permanent=False):
        now = self.clock()
        attempts = lease["attempts"] + 1
        exhausted = permanent or attempts >= MAX_ATTEMPTS
        with self.owned_transaction(lease) as db:
            db.execute(
                """UPDATE managed_block_leases SET attempts=?,last_error=?,observed_state='unknown',
                   next_retry_at=? WHERE id=?""",
                (attempts, reason, now + min(60, 2**attempts), lease["id"]),
            )
            if lease["desired_state"] == "present":
                if exhausted or now >= self.activation_limit(lease):
                    self.stop_activation(db, lease, now, reason)
                else:
                    self.stage(
                        db, lease, "action_unknown" if reason == "action_unknown" else "pending_execution"
                    )
            else:
                self.stage(db, lease, "unblock_failed" if exhausted else "unblock_pending")
                if exhausted:
                    db.execute("UPDATE managed_block_leases SET next_retry_at=-1 WHERE id=?", (lease["id"],))
                    self.lifecycle_event(db, lease, "response.unblock.completed", "unblock_failed", now)
                log.warning(
                    "managed.cleanup_overdue",
                    extra={"case_id": lease["case_id"], "details": {"code": reason}},
                )
            self.release(db, lease)

    def release(self, db, lease):
        db.execute(
            """UPDATE managed_block_leases SET execution_owner=NULL,execution_lease_until=NULL
               WHERE id=? AND execution_owner=?""",
            (lease["id"], lease["execution_owner"]),
        )

    def completed_event(self, db, lease):
        action = db.execute("SELECT * FROM actions WHERE id=?", (lease["action_id"],)).fetchone()
        self.store.queue_response(db, action)

    @staticmethod
    def lifecycle_event(db, lease, name, status, now, verification="not_verified"):
        event_id = f"{lease['id']}:{name}"
        payload = {
            "schema_version": 1,
            "event_id": event_id,
            "event": name,
            "case_id": lease["case_id"],
            "action_id": lease["action_id"],
            "ip": lease["source_ip"],
            "decision": "approve",
            "mode": MODE,
            "simulated": True,
            "blocked": False,
            "traffic_verified": False,
            "status": status,
            "verification_status": verification,
            "completed_at": now,
        }
        db.execute(
            """INSERT OR IGNORE INTO notification_outbox(id,case_id,payload,status,available)
               VALUES(?,?,?,'local_only',?)""",
            (event_id, lease["case_id"], json.dumps(payload), LOCAL_ONLY_AVAILABLE),
        )
