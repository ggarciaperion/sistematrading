# Pull Request: Atomic EXP-ID Generation

## PR Details
- **Title:** fix: atomic EXP-ID generation (operation_seq) to avoid race conditions
- **Base Branch:** main
- **Head Branch:** copilot/fix-operation-id-sequence-one-more-time

## Summary of Changes

This PR implements atomic EXP-ID generation to prevent race conditions when multiple concurrent requests create operations in the SQLite database.

**Changes made:**
- Added `import time` for retry/backoff logic
- **init_db()**: Creates a new table `operation_seq` (`id INTEGER PRIMARY KEY CHECK (id = 1), last_num INTEGER NOT NULL`) and inserts an initial row `(1, 1000)` if missing to seed the sequence
- **generar_idop(conn, retries=5)**: Uses `BEGIN IMMEDIATE` to obtain an exclusive write lock, reads `operation_seq.last_num`, increments and updates it atomically, commits and returns a new operation ID formatted as `EXP-XXXX`. The function includes retries with small backoff on `sqlite3.OperationalError` (e.g., database locked) and falls back to the legacy approach (reading the latest EXP- operation_id from operations table) if operation_seq is unavailable or unexpected errors occur
- **create_operation() POST flow**: Now uses `generar_idop(conn)` when inserting a new operation instead of inline ID generation

**Why:** Prevent race conditions and duplicate operation IDs when multiple concurrent create_operation requests run against an SQLite database.

## Testing Instructions

**1. Restart the app or run init_db() to ensure operation_seq was created and seeded:**
```bash
# The table should be created automatically on app startup
```

**2. In sqlite, verify the table exists and is seeded:**
```sql
SELECT * FROM operation_seq;
-- Should return: id=1, last_num=1000 (initially)
```

**3. Create several operations sequentially and verify operation_id values are sequential:**
- Create operations through the UI or API
- Verify IDs are: EXP-1001, EXP-1002, EXP-1003, etc.
- Check `operation_seq.last_num` increases with each operation

**4. Run concurrent POST requests to create_operation:**
```bash
# Example using curl in parallel (adjust URL and params as needed)
for i in {1..10}; do
  curl -X POST http://localhost:5000/create_operation \
    -d "client_db_id=1&operation_type=Compra&amount_usd=100&exchange_rate=3.8&source_account=ACC1&destination_account=ACC2" &
done
wait
```
- Verify no duplicate operation IDs were generated
- Verify no gaps in the sequence (unless expected due to failed transactions)
- Check database: `SELECT operation_id FROM operations WHERE operation_id LIKE 'EXP-%' ORDER BY operation_id;`

**5. Check logs for sqlite3.OperationalError:**
- The function retries with exponential backoff (0.05s, 0.10s, 0.15s, 0.20s, 0.25s)
- Under high concurrency, you may see retries in logs (if logging is enabled)
- Verify the system handles database locks gracefully

**6. Test fallback mode:**
- Manually drop or rename the `operation_seq` table
- Create a new operation
- Verify it falls back to the legacy method (reading from operations table)
- The operation should still be created with a valid EXP- ID

## Code Review Points

Please verify:
- ✅ init_db() creates operation_seq and seeds it properly with (1, 1000)
- ✅ generar_idop() is correct and robust:
  - Transaction control with BEGIN IMMEDIATE
  - Retries with exponential backoff on OperationalError
  - Proper rollback on errors
  - Fallback to legacy method if operation_seq unavailable
- ✅ create_operation() uses generar_idop(conn) correctly
- ✅ The changes maintain backward compatibility
- ✅ No existing functionality is broken

## Notes

- The operation_seq table uses a CHECK constraint (`CHECK (id = 1)`) to ensure only one row exists
- Initial seed value is 1000, so first generated ID will be EXP-1001
- The atomic approach using `BEGIN IMMEDIATE` prevents race conditions in SQLite
- Fallback ensures the system continues working even if operation_seq is missing

## Testing Results

All tests passed successfully:
- ✅ Sequential ID generation works correctly (EXP-1001 through EXP-1005)
- ✅ operation_seq counter increments properly
- ✅ Fallback mode functions correctly when operation_seq is unavailable
- ✅ Python syntax validation passed
- ✅ init_db() creates and seeds the table correctly
