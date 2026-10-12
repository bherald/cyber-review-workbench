"""One local SQLite action identity, claimed before effect and read back after save."""

import json
from pathlib import Path
import sqlite3

from .evidence import same_evidence


class Refused(RuntimeError):
    pass


class Ledger:
    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.execute("CREATE TABLE IF NOT EXISTS actions (action_id TEXT PRIMARY KEY, scope_sha256 TEXT NOT NULL, state TEXT NOT NULL, document TEXT NOT NULL)")
        self.db.commit()
        self.path.chmod(0o600)

    def claim(self, action_id, scope_sha256, action):
        document = {"action": action, "scope_sha256": scope_sha256}
        try:
            self.db.execute("INSERT INTO actions VALUES (?, ?, ?, ?)",
                            (action_id, scope_sha256, "started", json.dumps(document, sort_keys=True)))
            self.db.commit()
        except sqlite3.IntegrityError as error:
            self.db.rollback()
            raise Refused("Action already claimed. Read saved evidence; do not replay.") from error

    def complete(self, action_id, evidence, success, complete=True):
        row = self.db.execute("SELECT state, document FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        if row is None or row[0] != "started":
            raise Refused("Original started action receipt required.")
        document = json.loads(row[1])
        document.update(outcome="succeeded" if success and complete else "review_required",
                        result={"success": success, "evidence": evidence})
        state = "completed" if complete else "outcome_unknown"
        updated = self.db.execute("UPDATE actions SET state = ?, document = ? WHERE action_id = ? AND state = ?",
                                  (state, json.dumps(document, sort_keys=True), action_id, "started"))
        if updated.rowcount != 1:
            self.db.rollback()
            raise Refused("Receipt changed; preserve unknown outcome.")
        self.db.commit()
        saved = self.receipt(action_id)
        if saved["state"] != state or not same_evidence(saved["document"], document):
            raise Refused("Receipt readback failed. Do not replay.")
        return saved

    def receipt(self, action_id):
        row = self.db.execute("SELECT state, document FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        if row is None:
            raise Refused("Saved action receipt missing.")
        return {"state": row[0], "document": json.loads(row[1])}

    def receipts(self):
        rows = self.db.execute("SELECT state, document FROM actions ORDER BY action_id").fetchall()
        return [{"state": state, "document": json.loads(document)} for state, document in rows]

    def close(self):
        self.db.close()


def status(path):
    """Read existing local evidence without creating a DB or contacting a worker."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute("SELECT action_id, state FROM actions ORDER BY action_id").fetchall()
    return {"actions": [{"id": action_id, "state": state} for action_id, state in rows],
            "network_contacted": False, "automatic_replay_allowed": False,
            "operator_closed": False, "security_certification": False}
