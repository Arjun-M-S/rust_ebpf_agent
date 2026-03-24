import json
import hashlib

def verify_chain(wal_file):
    print(f"🔍 Verifying Blockchain Integrity for {wal_file}...")
    
    with open(wal_file, 'r') as f:
        lines = f.readlines()

    expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"

    for i, line in enumerate(lines):
        log = json.loads(line.strip())
        
        # 1. Check Link Integrity
        if log['prev_hash'] != expected_prev:
            print(f"[ALERT] Chain broken at Line {i+1}!")
            print(f"   Expected Prev: {expected_prev[:16]}...")
            print(f"   Actual Prev:   {log['prev_hash'][:16]}...")
            return

        # 2. Recompute Hash
        data_to_hash = f"{log['timestamp']}{log['uid']}{log['pid']}{log['process_name']}{log['prev_hash']}"
        computed_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

        # 3. Check Data Integrity
        if computed_hash != log['hash']:
            print(f"ALERT] Data tampering detected at Line {i+1}!")
            print(f"   Log has been modified since it was written.")
            return

        expected_prev = log['hash']

    print(f"All {len(lines)} logs verified. Chain is cryptographically secure.")

if __name__ == "__main__":
    verify_chain("/tmp/edr.wal")