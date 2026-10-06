# kvm-uintr

Standalone, experimental Linux KVM/VMX UINTR state bridge extracted from the
Flux experiment. This repository is independent of both gFlux and the Flux
kernel module. It does not install Flux devices, MPK hooks, scheduler probes or
the Flux posted-interrupt wakeup callback.

The module contains Linux 6.8 and 6.17 backends for Intel VMX with UINTR,
XSAVES and the VM-entry/exit UINV controls. It currently accepts host releases
`6.8.0-146-generic` and `6.17.13-flux`. It is disabled unless loaded with `enable=1`.
The standalone module has been built and tested on AR200CA (`ar200ca-225h`,
`100.100.0.18`, Linux `6.17.13-flux`).

Build and execute on the selected experiment host:

```sh
make KDIR=/lib/modules/$(uname -r)/build
sudo insmod kvm_uintr.ko enable=1
# Start the owned, non-nested KVM guest.
# Destroy all vCPUs before unloading; live state pins this module.
sudo rmmod kvm_uintr
```

Load only with no running VMs while the implementation is experimental. Use
`-cpu host,vmx=off` and an in-kernel irqchip for the intended L1 configuration. Nested virtualization,
migration/checkpoint state ABI and unsupported kernel versions are outside
the current validation scope. Guest MSR state is not exposed as a complete
userspace migration interface.

The standalone tests cover 100 VM exits with cross-core migration, CPUID/XSS
buffer sizing, rejected reserved MSR bits, 100 self notifications, 100 cross-vCPU
notifications, host UINTR/XSS preservation, and module load/unload. Run them on
an idle host with CPUs 2 and 4 available:

```sh
make -C tests
sudo python3 tests/run-smoke.py --host ar200ca-225h --output results/smoke
```

A Linux `6.8.0-146-generic` guest boots with this standalone module enabled.
Native Flux module load/unload also passes inside that guest. The original
seventeen-core memory comparison is a separate experiment; these small-VM
checks do not provide replacement performance results.

`tests/flux-guest-smoke.py` runs the original Flux yield and multiprocess-yield
programs inside an owned guest. Supply the native Flux module, runtime, libraries
and benchmark binaries as a separate payload. A guest whose CPUID omits TSC
frequency needs Flux's `tsc_early_khz` boot option; pass the actual virtual
frequency as `--tsc-khz`. Both cases pass on AR200CA with three vCPUs: one Flux
worker and two iokd service CPUs, plus the host VM backend CPU. Payload runtime
copies have only their ELF interpreter path relocated for the guest's libc;
the original binaries remain unchanged in the source experiment.

Implementation sources use GPL-2.0. Register layouts and ftrace symbol helpers
derive from Flux commit `8ffa052e4a2cd43070078d98e49169432714ef35`; extraction
retains source attribution. Intel's [VMX specification](https://cdrdv2-public.intel.com/825750/326019-sdm-vol-3c.pdf)
describes UINV state and virtualized SENDUIPI.
