#!/usr/bin/env python3
"""Run inside the owned Linux guest, using a separately supplied Flux payload."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import struct
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--module", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tsc-khz", type=int, default=0,
                        help="Actual virtual TSC frequency for Flux's boot override")
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.cpu_count() >= 3
    assert not Path("/sys/module/flux").exists()
    args.output.mkdir(parents=True, exist_ok=False)
    helper = None
    loaded = False
    created = []
    records = []
    sock = Path(f"/tmp/flux-kvm-smoke-{os.getpid()}.sock")
    payload = args.payload.resolve()
    loader = str(payload / "host-lib/ld-linux-x86-64.so.2")
    # Explicit ld.so invocation makes /proc/self/exe point to ld.so, breaking
    # Flux's bootstrap self-exec. Relocate only the copied ELF's interpreter.
    interpreter = Path("/opt/flux-smoke-ld.so")
    interpreter.write_bytes(Path(loader).read_bytes())
    interpreter.chmod(0o755)
    for name in ["flux", "flux-iokd"]:
        binary = payload / name
        data = bytearray(binary.read_bytes())
        assert data[:6] == b"\x7fELF\x02\x01"
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phsize, phnum = struct.unpack_from("<HH", data, 54)
        for index in range(phnum):
            offset = phoff + index * phsize
            if struct.unpack_from("<I", data, offset)[0] == 3:
                start = struct.unpack_from("<Q", data, offset + 8)[0]
                size = struct.unpack_from("<Q", data, offset + 32)[0]
                replacement = str(interpreter).encode() + b"\0"
                assert len(replacement) <= size
                data[start:start + size] = replacement.ljust(size, b"\0")
                break
        else:
            raise AssertionError("Missing ELF interpreter")
        binary.write_bytes(data)
    host_env = {**os.environ, "LD_LIBRARY_PATH": str(payload / "host-lib")}
    try:
        subprocess.run(["insmod", str(args.module)], check=True)
        loaded = True
        major = int(next(line.split()[0] for line in Path("/proc/devices").read_text().splitlines()
                         if line.split()[-1:] == ["flux"]))
        for minor, name in enumerate(["flux", "flux_uintr", "flux_mm"]):
            device = Path("/dev") / name
            expected = os.makedev(major, minor)
            if not device.exists():
                os.mknod(device, stat.S_IFCHR | 0o600, expected)
                created.append(device)
            assert device.stat().st_rdev == expected
        iokd_cfg = args.output / "iokd.json"
        iokd_cfg.write_text(json.dumps({"cpu_range": "0-2", "sock_path": str(sock),
                                        "no_network": True}, indent=2) + "\n")
        with (args.output / "iokd.log").open("wb") as out:
            helper = subprocess.Popen([str(payload / "flux-iokd"),
                                       "-c", str(iokd_cfg)], cwd=payload, stdout=out,
                                      stderr=subprocess.STDOUT, env=host_env, start_new_session=True,
                                      preexec_fn=lambda: os.sched_setaffinity(0, {0}))
        deadline = time.monotonic() + 15
        while not sock.is_socket():
            assert helper.poll() is None and time.monotonic() < deadline
            time.sleep(.05)
        boot_cmdline = "static_hugetlb=0"
        if args.tsc_khz:
            assert args.tsc_khz > 0
            boot_cmdline += f" tsc_early_khz={args.tsc_khz}"
        config = {"mem_size": "512M", "dma_size": "0", "nr_cpus": "1", "cpu_set": "1",
                  "boot_cmdline": boot_cmdline, "iok_sock_path": str(sock),
                  "ld_path": "/third-party/install/lib/ld-linux-x86-64.so.2",
                  "env": ["LANG=C", "PATH=/bin:/usr/bin", "LD_BIND_NOW=1",
                          "LD_LIBRARY_PATH=/third-party/install/lib:/lib/x86_64-linux-gnu"],
                  "hostfs_mounts": [f"{payload}/app:/bin",
                                    f"{payload}/third-party/install/lib:/third-party/install/lib",
                                    f"{payload}/third-party/install/lib:/lib64",
                                    "/etc:/etc", "/usr:/usr", "/lib:/lib"]}
        config_path = args.output / "run.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        for name, app in [("yield", ["/bin/bench", "yield"]),
                          ("yield-process", ["/bin/bench_multiproc", "yield", "2", "200000"])]:
            command = [str(payload / "flux"), "--multiproc",
                       "-c", str(config_path), "--", *app]
            with (args.output / f"{name}.stdout").open("wb") as out, \
                    (args.output / f"{name}.stderr").open("wb") as err:
                child = subprocess.Popen(command, cwd=payload, stdout=out, stderr=err,
                                         env=host_env, start_new_session=True,
                                         preexec_fn=lambda: os.sched_setaffinity(0, {2}))
                try:
                    result = child.wait(timeout=120)
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, 15)
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, 9)
                            child.wait()
            records.append({"case": name, "command": command, "exit": result})
            assert result == 0, records[-1]
            label = "yield" if name == "yield" else "yield_proc"
            assert f"RESULT\t{label}\t" in (args.output / f"{name}.stdout").read_text()
    finally:
        if helper is not None and helper.poll() is None:
            os.killpg(helper.pid, 15)
            try:
                helper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(helper.pid, 9)
                helper.wait()
        if loaded:
            deadline = time.monotonic() + 10
            while int(Path("/sys/module/flux/refcnt").read_text()):
                assert time.monotonic() < deadline, "Flux references did not drain"
                time.sleep(.05)
            subprocess.run(["rmmod", "flux"], check=True)
        for device in created:
            device.unlink()
        sock.unlink(missing_ok=True)
        (args.output / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        (args.output / "dmesg.log").write_text(subprocess.check_output(["dmesg"], text=True))
    print("PASS Flux-in-KVM yield and yield-process")


if __name__ == "__main__":
    main()
