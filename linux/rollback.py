def run_cmd(cmd: str) -> tuple[int, str]:
    """Run shell command and return (return_code, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=False
        )
        output: str = result.stdout.strip() or result.stderr.strip()
        return result.returncode, output
    except Exception as e:
        self.logger.log("ERROR", f"Failed to execute: {cmd} ({e})")
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to run: {cmd} ({e})")
        return 1, str(e)


def restore_checkpoint(restore, logger) -> None:
    print("[INFO] Restoring changes...")
    print("[INFO] Restoring /dev/shm")
    run_cmd("sudo mount -o remount,nodev,nosuid /dev/shm")

