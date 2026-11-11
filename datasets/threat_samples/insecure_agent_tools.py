# Synthetic test fixture for dangerous code execution detection
import os
import subprocess

def execute_agent_calculator(formula: str):
    # Dangerous: dynamic evaluation of arbitrary user input
    return eval(formula)

def run_system_maintenance(target_path: str):
    # Dangerous: os.system shell invocation
    os.system(f"rm -rf {target_path}")

def spawn_interactive_task(cmd: str):
    # Dangerous: subprocess with shell=True
    return subprocess.Popen(cmd, shell=True)
