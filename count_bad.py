import json

ADMIN_IP = "192.168.200.30"

def count_admin_access(file_path):
    count = 0

    with open(file_path, "r") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # Count once per JSON object / line if the admin IP appears anywhere
            if ADMIN_IP in line:
                count += 1
                try:
                    obj = json.loads(line)
                    cmd = obj.get("action_params", {}).get("command", "")
                    action = obj.get("action_name", "")
                    print(f"[LINE {i}] {action} | {cmd}")
                except json.JSONDecodeError:
                    print(f"[LINE {i}] {line[:200]}")

    print(f"\nTotal lines mentioning admin server: {count}")
    return count

count_admin_access("output/admin-server-no-guardrails_main_task_2026-04-20_13-12-03/actions.json")