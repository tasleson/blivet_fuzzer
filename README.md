# Blivet Fuzzer

*"Chaos is a ladder... to finding bugs in your storage stack."*

## What Is This Thing?

Ever wondered what would happen if you let a caffeinated Python script loose on your storage devices with instructions to "get creative"? Well, wonder no more!

This is a **storage configuration fuzzer** that uses [blivet](https://github.com/storaged-project/blivet) to randomly create increasingly chaotic combinations of:

- **Partitions** (the boring foundation)
- **LVM** (volume groups and logical volumes)
- **MD RAID** (RAID 0, 1, 5 - pick your poison)
- **BTRFS** (with subvolumes, because why not?)
- **Stratis** (fancy newfangled storage pooling)
- **LUKS encryption** (sprinkled on top like security confetti)
- **Various filesystems** (ext4, xfs, vfat... the usual suspects)

The fuzzer creates these configurations, mounts them, writes test files, reads them back, and then tears everything down. It's like a storage stress test that actually enjoys its job.

## What Could Possibly Go Wrong?

> **⚠️ WARNING: This program has ONE job - to DESTROY DATA.**
>
> It will cheerfully annihilate anything on the disks/devices you point it at. This is intentional. This is the point. Do NOT run this on:
> - Your laptop's main drive (unless you enjoy fresh starts)
> - Production servers (career-limiting move)
> - Your boss's computer (career-ending move)
> - Anything with data you'd miss

**DO** run it on:
- VMs (the natural habitat of chaos)
- Test systems
- Spare block devices you don't care about
- Loop devices created for this exact purpose

## Installation

```bash
# You'll need blivet (obviously)
sudo dnf install python3-blivet  # Fedora/RHEL
# or
sudo apt install python3-blivet  # Debian/Ubuntu (if available)

# Make it executable
chmod +x blivet_fuzzer.py
```

## Usage

### Basic Usage (Disk Images)

The safest way to run this is with temporary disk images:

```bash
sudo ./blivet_fuzzer.py --iterations 20
```

This creates temporary sparse files as virtual disks, fuzzes them, then cleans up.

### Advanced Usage (Real Block Devices)

If you're feeling brave (or have actual test hardware):

```bash
# WARNING: Everything on /dev/sdb and /dev/sdc will be DESTROYED
sudo ./blivet_fuzzer.py --block-device /dev/sdb --block-device /dev/sdc --iterations 50
```

### Fun Options

```bash
# Maximum chaos with logging
sudo ./blivet_fuzzer.py -i 100 --save-logs --log-dir /var/log/chaos

# Only test LVM and RAID (no exotic stuff)
sudo ./blivet_fuzzer.py --only-types lvm mdraid

# Avoid Stratis because it's giving you problems
sudo ./blivet_fuzzer.py --exclude-types stratis

# Reproducible chaos (same random seed = same configurations)
sudo ./blivet_fuzzer.py --seed 42 --iterations 10

# No encryption (living dangerously? or just faster testing?)
sudo ./blivet_fuzzer.py --no-encryption

# Only XFS filesystems (you have opinions)
sudo ./blivet_fuzzer.py --filesystems xfs

# Extra verbose for debugging
sudo ./blivet_fuzzer.py -v --debug-partitioning
```

## What Does Success Look Like?

```
FUZZING SUMMARY
======================================================================
Requested iterations: 10
Completed iterations: 10
Successful: 10
Failed: 0
Success rate: 100.0%
======================================================================
```

If you see `Success rate: 100.0%`, congratulations! Your storage stack survived the gauntlet.

If you see failures... well, that's why we're here, isn't it? Check the logs for what went wrong.

## Requirements

- **Root privileges** (it's messing with block devices, what did you expect?)
- **Python 3**
- **blivet library** (python3-blivet)
- **A sense of adventure**
- **Working backups** (just in case you ignore the warnings)

## How It Works

1. Creates random disk images (or uses your real devices)
2. Picks a random storage configuration type
3. Builds increasingly complex layer stacks (partitions → RAID → LVM → encryption → filesystem)
4. Mounts everything
5. Writes test files
6. Reads them back
7. Tears everything down
8. Repeats until you get bored or find bugs

## Exit Codes

- `0` - All iterations succeeded (boring but good)
- `1` - At least one iteration failed (interesting!)

## Tips

- Start with a small number of iterations (`-i 5`) to make sure it works
- Use `--save-logs` to capture detailed information about failures
- Press `Ctrl+C` to stop gracefully (it cleans up!)
- Use `--seed` if you find an interesting failure and want to reproduce it

## FAQ

**Q: Why would I want to do this?**
A: To find bugs in blivet, test storage drivers, or just watch your system create and destroy storage configurations like a digital sandcastle artist.

**Q: Is this safe?**
A: Define "safe." It's safe for finding bugs. Not safe for your data.

**Q: Can I run this in production?**
A: *Nervous laughter* No. Just... no.

**Q: What's the weirdest configuration it can create?**
A: Picture this: Partition → RAID5 → LVM → LUKS encryption → ext4. It's beautiful chaos.

**Q: It failed on iteration 37. What do I do?**
A: Check the logs! Use `--seed` to reproduce it. File a bug report. Feel accomplished.

## License

Whatever license blivet uses. This is a test tool, not production code. Use at your own risk. Backups are your friend.

## Contributing

Found a bug? Great! That's the whole point. Found a bug in the fuzzer itself? Even better - that's meta-fuzzing.

---

*Remember: With great power comes great responsibility. And with root access comes great potential for disk destruction.*
