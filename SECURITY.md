# Security scope

The demo starts its own synthetic server on `127.0.0.1` and accepts no remote
target. Use the explicit approval flag only for that local fixture. Keep the
generated evidence directory private and out of Git.

The SQLite ledger and evidence hashes provide local consistency checks. They
are not authenticated attestations or a substitute for protected custody,
target authorization and independent review in a deployed system.

If reporting a defect, provide a minimal synthetic reproducer. Keep customer
material, credentials and private target details out of public issues.
