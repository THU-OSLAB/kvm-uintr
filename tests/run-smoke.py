#!/usr/bin/env python3
"""Run built bare-KVM tests on an idle, explicitly selected experiment host."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time


def active_vms():
    found = []
    for process in Path("/proc").glob("[0-9]*"):
        try:
            if any("kvm-vm" in os.readlink(fd) or "kvm-vcpu" in os.readlink(fd)
                   for fd in (process / "fd").iterdir()):
                found.append(process.name)
        except (FileNotFoundError, ProcessLookupError):
            pass
    return found


def host_msrs():
    result = {}
    for cpu in [2, 4]:
        fd = os.open(f"/dev/cpu/{cpu}/msr", os.O_RDONLY)
        try:
            result[str(cpu)] = {
                hex(index): hex(int.from_bytes(os.pread(fd, 8, index), "little"))
                for index in [0xda0, *range(0x985, 0x98b)]
            }
        finally:
            os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Expected hostname; prevents wrong-host runs")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert platform.node() == args.host
    assert {2, 4}.issubset(os.sched_getaffinity(0))
    source = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=False)
    lock = open("/tmp/flux-ltp.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert not active_vms(), "Existing VMs prevent module-state tests"
    assert not Path("/sys/module/flux").exists(), "Native Flux must not be loaded on L0"
    assert not Path("/sys/module/kvm_uintr").exists()
    before = subprocess.check_output(["dmesg"], text=True)
    subprocess.run(["modprobe", "msr"], check=True)
    initial = host_msrs()
    results = {"host": platform.node(), "kernel": platform.release(), "before_msrs": initial,
               "cases": []}
    owned = False
    try:
        for parameter in ["enable=0", "enable=1"]:
            subprocess.run(["insmod", str(source / "kvm_uintr.ko"), parameter], check=True)
            owned = True
            if parameter == "enable=1":
                for name, guest, extra in [
                    ("msr-smoke", "msr", ["migrate"]),
                    ("self-uipi", "self-uipi", []),
                    ("cross-uipi", "cross-uipi", []),
                ]:
                    command = [str(source / f"tests/build/kvm-{name}"),
                               str(source / f"tests/build/{guest}-guest.bin"), *extra]
                    run = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    record = {"case": name, "command": command, "exit": run.returncode,
                              "stdout": run.stdout, "stderr": run.stderr}
                    results["cases"].append(record)
                    (args.output / f"{name}.json").write_text(json.dumps(record, indent=2) + "\n")
                    assert run.returncode == 0, record
                    assert not active_vms()
            deadline = time.monotonic() + 10
            while int(Path("/sys/module/kvm_uintr/refcnt").read_text()):
                assert time.monotonic() < deadline, "vCPU module references did not drain"
                time.sleep(.05)
            subprocess.run(["rmmod", "kvm_uintr"], check=True)
            owned = False
        results["after_msrs"] = host_msrs()
        assert results["after_msrs"] == initial, "Host UINTR/XSS state changed"
        after = subprocess.check_output(["dmesg"], text=True)
        assert after.startswith(before), "Kernel log wrapped; cannot audit by prefix"
        results["kernel_log"] = after[len(before):]
        assert not re.search(r"BUG:|WARNING:|Oops:|general protection fault|invalid opcode|Call Trace:",
                             results["kernel_log"]), results["kernel_log"]
        results["passed"] = True
    finally:
        if owned and not active_vms():
            subprocess.run(["rmmod", "kvm_uintr"], check=False)
        (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"passed": True, "cases": len(results["cases"]),
                      "host_state_preserved": True, "module_unloaded": True}))


if __name__ == "__main__":
    main()
