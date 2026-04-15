# Will extract the commands from an actions.json file and then run them manually in the terminal 
import json
import subprocess
import argparse
import time

def load_commands(path):
    commands = []
    with open(path, "r") as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get("type") == "LowLevelAction":
                    cmd = obj.get("action_params", {}).get("command")
                    if cmd:
                        commands.append(cmd)
            except json.JSONDecodeError:
                continue
    return commands


def run_commands(commands, dry_run=False, delay=0):
    for i, cmd in enumerate(commands):
        print(f"\n[{i+1}/{len(commands)}] $ {cmd}")

        if dry_run:
            continue

        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # stream output live
            while True:
                output = process.stdout.readline()
                if output:
                    print(output, end="")
                if process.poll() is not None:
                    break

            # print remaining stderr if any
            err = process.stderr.read()
            if err:
                print(err)

        except Exception as e:
            print(f"Error running command: {e}")

        if delay > 0:
            time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to actions.json")
    parser.add_argument("--dry", action="store_true", help="Print commands only")
    parser.add_argument("--delay", type=float, default=0, help="Delay between commands (seconds)")

    args = parser.parse_args()

    cmds = load_commands(args.file)
    print(f"Loaded {len(cmds)} commands")

    run_commands(cmds, dry_run=args.dry, delay=args.delay)