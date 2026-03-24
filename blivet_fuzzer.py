#!/usr/bin/env python3
"""
Blivet Random Storage Fuzzer (Enhanced)

This program randomly creates various storage configurations using blivet,
including combinations of:
- Partitions
- LVM (volume groups and logical volumes)
- MD RAID (RAID 0, 1, 5, 6, 10)
- BTRFS volumes and subvolumes
- Stratis pools and filesystems
- LUKS encryption
- Various filesystems
- Complex stacking of these technologies

It then mounts them, creates test files, and tears everything down.
This is useful for stress testing blivet and finding edge cases.

WARNING: This requires root privileges and creates real block devices.
         Only run on a test system or in a VM!
"""

import os
import sys
import random
import stat
import tempfile
import time
import argparse
import traceback
import json
import signal
from datetime import datetime
from collections import defaultdict

import blivet
import blivet.devicelibs.raid
from blivet.size import Size
from blivet.devices import LUKSDevice, DiskDevice, PartitionDevice
from blivet.formats import get_format
from blivet.util import set_up_logging, create_sparse_tempfile


class FuzzerConfig:
    """Configuration for the fuzzer"""

    def __init__(self):
        # Basic settings
        self.num_disks = 2
        self.iterations = 10
        self.verbose = False
        self.save_logs = False
        self.log_dir = "/tmp/blivet_fuzzer_logs"
        self.seed = None  # Will be set later if not provided
        self.debug_partitioning = False

        # Disk settings
        self.min_disk_size = 2  # GiB
        self.max_disk_size = 10  # GiB
        self.block_devices = []  # Real block devices to use instead of disk images

        # Partition/LV settings
        # Note: min size is 512 MiB to support XFS (which requires at least 512 MiB)
        self.min_device_size = Size("512 MiB")
        self.max_device_size = Size("2 GiB")

        # Available storage types
        self.storage_types = ["partition", "lvm", "mdraid", "btrfs", "stratis", "stacked"]

        # Available filesystems
        self.filesystems = ["ext4", "ext3", "ext2", "xfs", "vfat"]

        # Feature toggles
        self.use_encryption = True
        self.encryption_probability = 0.5  # 50% chance

        # MD RAID settings
        self.raid_levels = ["raid0", "raid1", "raid5"]  # raid6, raid10 need 4+ disks

        # BTRFS settings
        self.btrfs_subvolumes = True
        self.max_subvolumes = 3

        # Stratis settings
        self.stratis_encrypted_probability = 0.3  # 30% chance

    def to_dict(self):
        """Convert config to dictionary for JSON serialization"""
        return {
            "num_disks": self.num_disks,
            "block_devices": self.block_devices,
            "iterations": self.iterations,
            "verbose": self.verbose,
            "seed": self.seed,
            "storage_types": self.storage_types,
            "filesystems": self.filesystems,
            "use_encryption": self.use_encryption,
            "encryption_probability": self.encryption_probability,
            "raid_levels": self.raid_levels,
        }

    def exclude_storage_type(self, storage_type):
        """Exclude a storage type from random selection"""
        if storage_type in self.storage_types:
            self.storage_types.remove(storage_type)

    def set_filesystems(self, filesystems):
        """Set specific filesystems to use"""
        self.filesystems = filesystems


class FailureInfo:
    """Track information about a failure"""

    def __init__(self, iteration, config_type, error, traceback_str):
        self.iteration = iteration
        self.config_type = config_type
        self.error = str(error)
        self.traceback = traceback_str
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "iteration": self.iteration,
            "config_type": self.config_type,
            "error": self.error,
            "traceback": self.traceback,
            "timestamp": self.timestamp
        }


# ============================================================================
# Layer Stacking Architecture
# ============================================================================

class Layer:
    """Base class for storage layers that can be stacked"""

    def __init__(self, fuzzer):
        """
        :param BlivetFuzzerEnhanced fuzzer: Reference to the fuzzer
        """
        self.fuzzer = fuzzer
        self.name = self.__class__.__name__

    def can_stack_on(self, parent_devices):
        """
        Check if this layer can be stacked on the given parent devices

        :param list parent_devices: List of parent devices
        :return: True if this layer can be created on these parents
        :rtype: bool
        """
        raise NotImplementedError

    def create(self, parent_devices):
        """
        Create this layer on top of parent devices

        :param list parent_devices: List of parent devices to build on
        :return: List of created devices that can be used as parents for next layer
        :rtype: list
        """
        raise NotImplementedError

    def log(self, message):
        """Helper to log with layer name"""
        self.fuzzer.log(f"  [{self.name}] {message}")


class PartitionLayer(Layer):
    """Creates partitions on disk devices"""

    def can_stack_on(self, parent_devices):
        # Can partition disks only
        self.log(f"checking if we can partition on parent_devices {parent_devices}")

        if not parent_devices:
            return False
        # Check if all parents are disk devices by checking if they're in disk_images
        # or if they have the isDisk property
        for dev in parent_devices:

            # Check if it's a disk by seeing if it's in the disk images
            if dev.name in self.fuzzer.blivet.disk_images:
                continue
            # Or check if it has the isDisk attribute and it's True
            if hasattr(dev, 'isDisk') and dev.isDisk:
                continue
            # Or check if it's an instance of DiskDevice
            if isinstance(dev, DiskDevice):
                continue
            # Otherwise, it's not a disk
            return False
        return True

    def create(self, parent_devices):
        """Create partitions on parent disk devices"""
        # If we have multiple disks, partition each one (for RAID scenarios)
        # If we have one disk, create 1-3 partitions on it
        created_partitions = []

        if len(parent_devices) > 1:
            # Multiple disks: create one partition on each (for RAID)
            self.log(f"Creating partitions on {len(parent_devices)} disks")
            for disk in parent_devices:
                # Initialize the disk
                self.fuzzer.blivet.initialize_disk(disk)

                # Create one partition using most of the disk
                overhead = Size("1 MiB")
                available = disk.size - overhead
                size = available * 0.95  # Use 95% of disk

                self.log(f"{disk.name}: partition of {size}")
                part = self.fuzzer.blivet.new_partition(size=size)
                self.fuzzer.blivet.create_device(part)
                created_partitions.append(part)
        else:
            # Single disk: create 1-3 partitions
            disk = parent_devices[0]
            self.log(f"Creating partitions on {disk.name} (size: {disk.size})")

            # Initialize the disk with a partition table
            self.fuzzer.blivet.initialize_disk(disk)

            # Calculate available space
            overhead = Size("1 MiB")
            available = disk.size - overhead
            num_partitions = random.randint(1, 3)
            self.log(f"Creating {num_partitions} partition(s)")

            buffer_factor = 0.95
            size_budget = (available * buffer_factor) / num_partitions

            for i in range(num_partitions):
                max_size = min(size_budget, self.fuzzer.config.max_device_size)
                min_size = self.fuzzer.config.min_device_size

                if max_size < min_size:
                    size = max_size
                else:
                    min_mb = int(min_size.convert_to("MiB"))
                    max_mb = int(max_size.convert_to("MiB"))
                    size = Size(f"{random.randint(min_mb, max_mb)} MiB")

                self.log(f"Partition {i+1}: {size}")
                part = self.fuzzer.blivet.new_partition(size=size)
                self.fuzzer.blivet.create_device(part)
                created_partitions.append(part)

        # Allocate all partitions
        blivet.partitioning.do_partitioning(self.fuzzer.blivet)
        self.log(f"Created {len(created_partitions)} partition(s) total")

        return created_partitions


class LVMLayer(Layer):
    """Creates LVM volume group and logical volumes"""

    def can_stack_on(self, parent_devices):
        # Can create LVM on partitions, raid arrays, or encrypted devices
        # Basically anything that can be formatted as lvmpv
        return len(parent_devices) > 0

    def create(self, parent_devices):
        """Create VG on parents and create 1-4 LVs"""
        self.log(f"Creating LVM on {len(parent_devices)} device(s)")

        # Format parent devices as PVs
        for pv in parent_devices:
            pv_fmt = get_format(fmt_type="lvmpv", device=pv.path)
            self.fuzzer.blivet.format_device(pv, pv_fmt)

        # Create VG
        vg = self.fuzzer.blivet.new_vg(parents=parent_devices, name="fuzz_vg")
        self.fuzzer.blivet.create_device(vg)
        self.log(f"Created VG: {vg.name} ({vg.size})")
        self.fuzzer.stats["lvm"] += 1

        # Calculate available space
        vg_available = vg.size * 0.95
        num_lvs = random.randint(1, 4)
        self.log(f"Creating {num_lvs} LV(s)")

        created_lvs = []
        size_budget = vg_available / num_lvs

        for i in range(num_lvs):
            max_size = min(size_budget, self.fuzzer.config.max_device_size)
            min_size = self.fuzzer.config.min_device_size

            if max_size < min_size:
                size = max_size
            else:
                min_mb = int(min_size.convert_to("MiB"))
                max_mb = int(max_size.convert_to("MiB"))
                size = Size(f"{random.randint(min_mb, max_mb)} MiB")

            self.log(f"LV {i+1}: {size}")
            lv = self.fuzzer.blivet.new_lv(size=size, parents=[vg], name=f"lv{i}")
            self.fuzzer.blivet.create_device(lv)
            created_lvs.append(lv)

        return created_lvs


class MDRaidLayer(Layer):
    """Creates MD RAID arrays"""

    def can_stack_on(self, parent_devices):
        # Need at least 2 devices for RAID
        # Can create RAID on partitions or other block devices, but not raw disks
        if len(parent_devices) < 2:
            return False
        # RAID should be on partitions, not raw disks
        return not any(isinstance(dev, DiskDevice) for dev in parent_devices)

    def create(self, parent_devices):
        """Create RAID array from parent devices"""
        # Choose RAID level based on number of available devices
        available_levels = []
        num_devices = len(parent_devices)

        if num_devices >= 2:
            available_levels.extend(["raid0", "raid1"])
        if num_devices >= 3:
            available_levels.append("raid5")
        if num_devices >= 4:
            available_levels.extend(["raid6", "raid10"])

        raid_level_str = random.choice(available_levels)
        raid_level = getattr(blivet.devicelibs.raid, raid_level_str.upper())

        self.log(f"Creating {raid_level_str} with {num_devices} members")

        # Format parent devices as mdmember
        for member in parent_devices:
            md_fmt = get_format(fmt_type="mdmember", device=member.path)
            self.fuzzer.blivet.format_device(member, md_fmt)

        # Create MD array
        array = self.fuzzer.blivet.new_mdarray(
            name="fuzz_raid",
            parents=parent_devices,
            level=raid_level,
            total_devices=num_devices,
            member_devices=num_devices
        )
        self.fuzzer.blivet.create_device(array)
        self.log(f"Created MD array: {array.name}")
        self.fuzzer.stats["mdraid"] += 1

        return [array]


class EncryptionLayer(Layer):
    """Adds LUKS encryption"""

    def can_stack_on(self, parent_devices):
        # Can encrypt any block device
        return len(parent_devices) > 0

    def create(self, parent_devices):
        """Add LUKS encryption to parent devices"""
        self.log(f"Encrypting {len(parent_devices)} device(s)")

        encrypted_devices = []
        for parent in parent_devices:
            self.log(f"LUKS on {parent.name}")

            # Format as LUKS
            luks_fmt = get_format(fmt_type="luks", device=parent.path, passphrase="test123")
            self.fuzzer.blivet.format_device(parent, luks_fmt)

            # Create LUKS device
            luks_dev = LUKSDevice(
                name=f"luks-{parent.name}",
                size=parent.size,
                parents=[parent]
            )
            self.fuzzer.blivet.create_device(luks_dev)
            encrypted_devices.append(luks_dev)
            self.fuzzer.stats["encrypted"] += 1

        return encrypted_devices


class FilesystemLayer(Layer):
    """Adds filesystem formatting (terminal layer)"""

    def can_stack_on(self, parent_devices):
        # Can format any block device
        return len(parent_devices) > 0

    def create(self, parent_devices):
        """Format parent devices with filesystems"""
        self.log(f"Formatting {len(parent_devices)} device(s)")

        formatted_devices = []
        for parent in parent_devices:
            fs_type = self.fuzzer.get_compatible_filesystem(parent.size)
            self.log(f"{parent.name} -> {fs_type}")

            # Format with filesystem
            fs_fmt = get_format(fmt_type=fs_type, device=parent.path)
            self.fuzzer.blivet.format_device(parent, fs_fmt)
            formatted_devices.append(parent)

        return formatted_devices


class LayerStack:
    """Manages a stack of layers"""

    def __init__(self, fuzzer):
        self.fuzzer = fuzzer
        self.layers = []

    def add_layer(self, layer_class):
        """Add a layer to the stack"""
        self.layers.append(layer_class)

    def create(self, initial_devices):
        """
        Create the full stack starting from initial devices

        :param list initial_devices: Starting devices (typically disks)
        :return: Final devices after all layers applied
        :rtype: list
        """
        current_devices = initial_devices

        for layer_class in self.layers:
            layer = layer_class(self.fuzzer)

            if not layer.can_stack_on(current_devices):
                raise ValueError(
                    f"Layer {layer.name} cannot be stacked on devices: "
                    f"{[d.name for d in current_devices]}"
                )

            current_devices = layer.create(current_devices)

            if not current_devices:
                raise ValueError(f"Layer {layer.name} created no devices")

        return current_devices

    def get_description(self):
        """Get a human-readable description of the stack"""
        return " -> ".join(layer.__name__.replace("Layer", "") for layer in self.layers)


class StackGenerator:
    """Generates random valid layer stacks"""

    # Define valid layer sequences
    # Each tuple is (layer_class, can_be_terminal, probability_weight)
    LAYER_TYPES = [
        (PartitionLayer, False, 1.0),    # Always create partitions on disks
        (LVMLayer, False, 0.6),          # 60% chance to add LVM
        (MDRaidLayer, False, 0.4),       # 40% chance to add RAID
        (EncryptionLayer, False, 0.5),   # 50% chance to add encryption
        (FilesystemLayer, True, 1.0),    # Always end with filesystem
    ]

    def __init__(self, fuzzer):
        self.fuzzer = fuzzer

    def generate_random_stack(self):
        """
        Generate a random valid layer stack

        :return: LayerStack object
        :rtype: LayerStack
        """
        stack = LayerStack(self.fuzzer)

        # Always start with partitions on disks
        stack.add_layer(PartitionLayer)
        current_layer_type = "partition"

        # Now randomly add intermediate layers
        # Possible sequences:
        # - partition -> encrypt -> fs
        # - partition -> lvm -> fs
        # - partition -> lvm -> encrypt -> fs
        # - partition -> encrypt -> lvm -> fs
        # - partition -> raid -> fs
        # - partition -> raid -> lvm -> fs
        # - partition -> raid -> encrypt -> fs
        # etc.

        # After partitions, optionally add RAID if we have multiple disks
        num_disks = self.fuzzer.config.num_disks
        if num_disks >= 2 and random.random() < 0.3:  # 30% chance
            stack.add_layer(MDRaidLayer)
            current_layer_type = "raid"

        # Decide whether to add LVM (50% chance)
        if random.random() < 0.5:
            stack.add_layer(LVMLayer)
            current_layer_type = "lvm"

        # Decide whether to add encryption
        if random.random() < self.fuzzer.config.encryption_probability:
            stack.add_layer(EncryptionLayer)
            current_layer_type = "encrypt"

        # Always end with filesystem
        stack.add_layer(FilesystemLayer)

        return stack


class BlivetFuzzerEnhanced:
    """Enhanced random storage configuration generator and tester"""

    def __init__(self, config):
        """
        Initialize the fuzzer

        :param FuzzerConfig config: Configuration object
        """
        self.config = config

        if config.verbose:
            set_up_logging()

        self.disk_files = []
        self.using_real_devices = bool(config.block_devices)
        self.blivet = None
        self.iteration_count = 0
        self.iterations = 0  # Will be set in run()
        self.success_count = 0
        self.failure_count = 0

        # Statistics
        self.stats = defaultdict(int)
        self.failures = []

        # Signal handling
        self.interrupted = False
        self.original_sigint_handler = None

        # Create log directory if needed
        if config.save_logs:
            os.makedirs(config.log_dir, exist_ok=True)

    def log(self, message, level="INFO"):
        """Print a message with iteration prefix and optionally save to file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [Iter {self.iteration_count}] [{level}] {message}"
        print(formatted)

        if self.config.save_logs:
            log_file = os.path.join(self.config.log_dir, f"iteration_{self.iteration_count}.log")
            with open(log_file, "a") as f:
                f.write(formatted + "\n")

    def log_error(self, message, exc_info=None):
        """Log an error with optional exception info"""
        self.log(message, level="ERROR")
        if exc_info:
            tb = traceback.format_exc()
            self.log(f"Traceback:\n{tb}", level="ERROR")
            return tb
        return None

    def signal_handler(self, signum, frame):
        """Handle SIGINT (Ctrl+C) gracefully"""
        if not self.interrupted:
            print("\n\n" + "=" * 70)
            print("INTERRUPT RECEIVED - Cleaning up...")
            print("=" * 70)
            self.interrupted = True
        else:
            # Second Ctrl+C - force exit
            print("\nForce exiting without cleanup!")
            sys.exit(1)

    def setup_signal_handlers(self):
        """Install signal handlers"""
        self.original_sigint_handler = signal.signal(signal.SIGINT, self.signal_handler)

    def restore_signal_handlers(self):
        """Restore original signal handlers"""
        if self.original_sigint_handler:
            signal.signal(signal.SIGINT, self.original_sigint_handler)

    def save_failure_info(self, config_type, error, tb):
        """Save detailed failure information"""
        failure = FailureInfo(self.iteration_count, config_type, error, tb)
        self.failures.append(failure)

        if self.config.save_logs:
            failure_file = os.path.join(
                self.config.log_dir,
                f"failure_{self.iteration_count}.json"
            )
            with open(failure_file, "w") as f:
                json.dump(failure.to_dict(), f, indent=2)

    def setup_disks(self):
        """Create disk images for testing or use real block devices"""
        self.blivet = blivet.Blivet()

        if self.config.block_devices:
            # Use real block devices
            self.log(f"Setting up {len(self.config.block_devices)} real block device(s)...")
            for i, block_dev in enumerate(self.config.block_devices):
                if not os.path.exists(block_dev):
                    raise ValueError(f"Block device does not exist: {block_dev}")
                if not os.path.isabs(block_dev):
                    raise ValueError(f"Block device path must be absolute: {block_dev}")

                # Verify it's actually a block device
                mode = os.stat(block_dev).st_mode
                if not stat.S_ISBLK(mode):
                    raise ValueError(f"Path is not a block device: {block_dev}")

                self.blivet.disk_images[f"disk{i}"] = block_dev
                self.log(f"  Using disk{i}: {block_dev}")

            # Update num_disks to match number of provided devices
            self.config.num_disks = len(self.config.block_devices)
        else:
            # Create disk images
            self.log(f"Setting up {self.config.num_disks} disk image(s)...")
            for i in range(self.config.num_disks):
                size = random.randint(self.config.min_disk_size, self.config.max_disk_size)
                disk_file = create_sparse_tempfile(f"fuzz_disk{i}", Size(f"{size} GiB"))
                self.disk_files.append(disk_file)
                self.blivet.disk_images[f"disk{i}"] = disk_file
                self.log(f"  Created disk{i}: {size} GiB")

        self.blivet.reset()

    def cleanup_disks(self):
        """Remove disk images or teardown real block devices"""
        if self.using_real_devices:
            self.log("Tearing down real block devices...")
        else:
            self.log("Cleaning up disk images...")

        if self.blivet:
            try:
                self.blivet.devicetree.teardown_disk_images()
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.log_error(f"Error during teardown: {e}")

        # Only delete temporary disk files, not real block devices
        if not self.using_real_devices:
            for disk_file in self.disk_files:
                try:
                    if os.path.exists(disk_file):
                        os.unlink(disk_file)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    self.log_error(f"Failed to remove {disk_file}: {e}")

        self.disk_files = []

    def random_size(self):
        """Generate a random size for partitions/LVs"""
        min_mb = int(self.config.min_device_size.convert_to("MiB"))
        max_mb = int(self.config.max_device_size.convert_to("MiB"))
        size_mb = random.randint(min_mb, max_mb)
        return Size(f"{size_mb} MiB")

    def get_min_filesystem_size(self, fs_type):
        """Get minimum size requirement for a filesystem type

        :param str fs_type: filesystem type
        :return: minimum size required
        :rtype: Size
        """
        # XFS requires at least 512 MiB
        if fs_type == "xfs":
            return Size("512 MiB")
        # Most other filesystems are fine with smaller sizes
        return Size("16 MiB")

    def get_compatible_filesystem(self, size):
        """Choose a filesystem type compatible with the given size

        :param Size size: device size
        :return: compatible filesystem type
        :rtype: str
        """
        # Filter filesystems that fit the size
        compatible = [fs for fs in self.config.filesystems
                     if size >= self.get_min_filesystem_size(fs)]

        if not compatible:
            # Fallback to ext4 if nothing fits (shouldn't happen in practice)
            self.log_error(f"No compatible filesystem for size {size}, defaulting to ext4")
            return "ext4"

        return random.choice(compatible)

    def random_filesystem(self):
        """Choose a random filesystem type (use get_compatible_filesystem for size-aware selection)"""
        return random.choice(self.config.filesystems)

    def should_encrypt(self):
        """Determine if encryption should be used"""
        if not self.config.use_encryption:
            return False
        return random.random() < self.config.encryption_probability

    def create_random_partition_layout(self):
        """Create a random partition-based configuration"""
        self.log("Creating partition-based layout...")
        self.stats["partition"] += 1

        # Pick a random disk
        disk_name = f"disk{random.randint(0, self.config.num_disks - 1)}"
        disk = self.blivet.devicetree.get_device_by_name(disk_name)

        self.log(f"  Using disk: {disk_name} (size: {disk.size})")

        # Initialize the disk with a partition table
        self.blivet.initialize_disk(disk)

        # Calculate available space (account for partition table overhead ~1 MiB)
        overhead = Size("1 MiB")
        available = disk.size - overhead

        # Create 1-3 partitions
        num_partitions = random.randint(1, 3)
        self.log(f"  Creating {num_partitions} partition(s)")

        created_devices = []
        total_requested = Size(0)

        # Calculate size budget per partition (with some buffer for alignment)
        buffer_factor = 0.95  # Use 95% to account for alignment
        size_budget = (available * buffer_factor) / num_partitions

        for i in range(num_partitions):
            # Use a random size up to the budget, but at least 100 MiB
            max_size = min(size_budget, self.config.max_device_size)
            min_size = self.config.min_device_size

            if max_size < min_size:
                # If budget is too small, use the budget
                size = max_size
            else:
                # Random size within budget
                min_mb = int(min_size.convert_to("MiB"))
                max_mb = int(max_size.convert_to("MiB"))
                size_mb = random.randint(min_mb, max_mb)
                size = Size(f"{size_mb} MiB")

            total_requested += size
            use_encryption = self.should_encrypt()
            fs_type = self.get_compatible_filesystem(size)

            if use_encryption:
                self.log(f"    Partition {i+1}: {size}, LUKS -> {fs_type}")
                self.stats["encrypted"] += 1
                # Create partition with LUKS
                part = self.blivet.new_partition(
                    size=size,
                    fmt_type="luks",
                    fmt_args={"passphrase": "test123"}
                )
                self.blivet.create_device(part)

                # Create LUKS device on top
                luks_dev = LUKSDevice(
                    name=f"luks-{part.name}",
                    size=part.size,
                    parents=[part]
                )
                self.blivet.create_device(luks_dev)

                # Format LUKS device with filesystem
                luks_fmt = get_format(fmt_type=fs_type, device=luks_dev.path)
                self.blivet.format_device(luks_dev, luks_fmt)

                created_devices.append(luks_dev)
            else:
                self.log(f"    Partition {i+1}: {size}, {fs_type}")
                # Create regular partition with filesystem
                part = self.blivet.new_partition(
                    size=size,
                    fmt_type=fs_type
                )
                self.blivet.create_device(part)
                created_devices.append(part)

        self.log(f"  Total requested: {total_requested} / Available: ~{available}")

        # Allocate partitions
        try:
            if self.config.debug_partitioning:
                self.log(f"  DEBUG: Attempting to allocate {len(created_devices)} partition(s)")
                for idx, dev in enumerate(created_devices):
                    parent = dev.parents[0] if dev.parents else None
                    if parent and hasattr(parent, 'req_size'):
                        self.log(f"  DEBUG:   Partition {idx}: req_size={parent.req_size}, req_base_size={parent.req_base_size}, req_grow={parent.req_grow}")

            blivet.partitioning.do_partitioning(self.blivet)
        except Exception as e:
            self.log_error(f"  Partitioning failed! Requested {total_requested} on {disk.size} disk")
            if self.config.debug_partitioning:
                # Show disk free space info
                self.log(f"  DEBUG: Disk format: {disk.format.type if disk.format else 'None'}")
                self.log(f"  DEBUG: Pending partitions in devicetree:")
                for dev in self.blivet.devicetree.devices:
                    if hasattr(dev, 'req_size') and dev.req_size:
                        self.log(f"  DEBUG:   {dev.name}: req_size={dev.req_size}")
            else:
                self.log("  TIP: Run with --debug-partitioning for more details")
            raise

        return created_devices

    def create_random_lvm_layout(self):
        """Create a random LVM-based configuration"""
        self.log("Creating LVM-based layout...")
        self.stats["lvm"] += 1

        # Pick 1-2 disks for PVs
        num_pvs = random.randint(1, min(2, self.config.num_disks))
        selected_disks = random.sample(range(self.config.num_disks), num_pvs)

        self.log(f"  Using {num_pvs} disk(s) for PVs: {selected_disks}")

        pvs = []
        for disk_idx in selected_disks:
            disk_name = f"disk{disk_idx}"
            disk = self.blivet.devicetree.get_device_by_name(disk_name)

            # Initialize disk
            self.blivet.initialize_disk(disk)

            # Create a partition for PV - ensure it fits on disk
            overhead = Size("1 MiB")
            available = disk.size - overhead
            max_pv_size = min(available * 0.95, Size("5 GiB"))
            min_pv_size = Size("1 GiB")

            if max_pv_size < min_pv_size:
                pv_size = max_pv_size
            else:
                min_gib = int(min_pv_size.convert_to("GiB"))
                max_gib = int(max_pv_size.convert_to("GiB"))
                pv_size = Size(f"{random.randint(min_gib, max_gib)} GiB")

            pv = self.blivet.new_partition(size=pv_size, fmt_type="lvmpv")
            self.blivet.create_device(pv)
            pvs.append(pv)
            self.log(f"    PV on disk{disk_idx}: {pv_size} (disk size: {disk.size})")

        # Allocate partitions
        try:
            blivet.partitioning.do_partitioning(self.blivet)
        except Exception as e:
            self.log_error(f"  PV partitioning failed!")
            if not self.config.debug_partitioning:
                self.log("  TIP: Run with --debug-partitioning for more details")
            raise

        # Create VG
        vg = self.blivet.new_vg(parents=pvs, name="fuzz_vg")
        self.blivet.create_device(vg)
        self.log(f"  Created VG: {vg.name} ({vg.size})")

        # Calculate available space in VG for LVs
        # Account for LVM metadata overhead - use 95% of VG size to be safe
        vg_available = vg.size * 0.95

        # Create 1-4 LVs
        num_lvs = random.randint(1, 4)
        self.log(f"  Creating {num_lvs} LV(s)")

        created_devices = []
        total_lv_size = Size(0)

        # Calculate size budget per LV
        size_budget = vg_available / num_lvs

        for i in range(num_lvs):
            # Budget LV size to fit in available VG space
            max_size = min(size_budget, self.config.max_device_size)
            min_size = self.config.min_device_size

            if max_size < min_size:
                size = max_size
            else:
                min_mb = int(min_size.convert_to("MiB"))
                max_mb = int(max_size.convert_to("MiB"))
                size_mb = random.randint(min_mb, max_mb)
                size = Size(f"{size_mb} MiB")

            total_lv_size += size
            use_encryption = self.should_encrypt()
            fs_type = self.get_compatible_filesystem(size)

            if use_encryption:
                self.log(f"    LV {i+1}: {size}, LUKS -> {fs_type}")
                self.stats["encrypted"] += 1
                # Create LV with LUKS
                lv = self.blivet.new_lv(
                    fmt_type="luks",
                    fmt_args={"passphrase": "test123"},
                    size=size,
                    parents=[vg],
                    name=f"lv{i}"
                )
                self.blivet.create_device(lv)

                # Create LUKS device
                luks_dev = LUKSDevice(
                    name=f"luks-{lv.name}",
                    size=lv.size,
                    parents=[lv]
                )
                self.blivet.create_device(luks_dev)

                # Format with filesystem
                luks_fmt = get_format(fmt_type=fs_type, device=luks_dev.path)
                self.blivet.format_device(luks_dev, luks_fmt)

                created_devices.append(luks_dev)
            else:
                self.log(f"    LV {i+1}: {size}, {fs_type}")
                # Create regular LV
                lv = self.blivet.new_lv(
                    fmt_type=fs_type,
                    size=size,
                    parents=[vg],
                    name=f"lv{i}"
                )
                self.blivet.create_device(lv)
                created_devices.append(lv)

        self.log(f"  Total LV size: {total_lv_size} / VG available: ~{vg_available} (VG size: {vg.size})")

        return created_devices

    def create_random_mdraid_layout(self):
        """Create a random MD RAID-based configuration"""
        self.log("Creating MD RAID-based layout...")
        self.stats["mdraid"] += 1

        # Choose RAID level
        raid_level_str = random.choice(self.config.raid_levels)
        raid_level = getattr(blivet.devicelibs.raid, raid_level_str.upper())

        # Determine number of members needed
        min_members = {
            "raid0": 2,
            "raid1": 2,
            "raid5": 3,
            "raid6": 4,
            "raid10": 4
        }

        needed = min_members.get(raid_level_str, 2)
        num_members = min(needed, self.config.num_disks)

        if num_members < needed:
            self.log(f"  Not enough disks for {raid_level_str}, need {needed}, have {num_members}")
            # Fall back to partition layout
            return self.create_random_partition_layout()

        self.log(f"  RAID level: {raid_level_str}, members: {num_members}")

        # Create partitions for RAID members
        selected_disks = random.sample(range(self.config.num_disks), num_members)
        members = []

        for disk_idx in selected_disks:
            disk_name = f"disk{disk_idx}"
            disk = self.blivet.devicetree.get_device_by_name(disk_name)
            self.blivet.initialize_disk(disk)

            # Ensure member partition fits on disk
            overhead = Size("1 MiB")
            available = disk.size - overhead
            max_size = min(available * 0.95, self.config.max_device_size)
            min_size = self.config.min_device_size

            if max_size < min_size:
                member_size = max_size
            else:
                min_mb = int(min_size.convert_to("MiB"))
                max_mb = int(max_size.convert_to("MiB"))
                size_mb = random.randint(min_mb, max_mb)
                member_size = Size(f"{size_mb} MiB")

            part = self.blivet.new_partition(
                size=member_size,
                fmt_type="mdmember",
                parents=[disk]
            )
            self.blivet.create_device(part)
            members.append(part)
            self.log(f"    Member on disk{disk_idx}: {member_size} (disk size: {disk.size})")

        # Allocate partitions
        try:
            blivet.partitioning.do_partitioning(self.blivet)
        except Exception as e:
            self.log_error(f"  RAID member partitioning failed!")
            if not self.config.debug_partitioning:
                self.log("  TIP: Run with --debug-partitioning for more details")
            raise

        # Create MD array
        array = self.blivet.new_mdarray(
            name="fuzz_raid",
            parents=members,
            level=raid_level,
            total_devices=num_members,
            member_devices=num_members
        )
        self.blivet.create_device(array)
        self.log(f"  Created MD array: {array.name}")

        # Decide whether to encrypt and add filesystem
        use_encryption = self.should_encrypt()
        fs_type = self.get_compatible_filesystem(array.size)

        created_devices = []

        if use_encryption:
            self.log(f"  MD array -> LUKS -> {fs_type}")
            self.stats["encrypted"] += 1

            # Format array as LUKS
            luks_fmt = get_format(fmt_type="luks", device=array.path, passphrase="test123")
            self.blivet.format_device(array, luks_fmt)

            # Create LUKS device
            luks_dev = LUKSDevice(
                name=f"luks-{array.name}",
                size=array.size,
                parents=[array]
            )
            self.blivet.create_device(luks_dev)

            # Format with filesystem
            fs_fmt = get_format(fmt_type=fs_type, device=luks_dev.path)
            self.blivet.format_device(luks_dev, fs_fmt)

            created_devices.append(luks_dev)
        else:
            self.log(f"  MD array -> {fs_type}")

            # Format array directly with filesystem
            fs_fmt = get_format(fmt_type=fs_type, device=array.path)
            self.blivet.format_device(array, fs_fmt)

            created_devices.append(array)

        return created_devices

    def create_random_btrfs_layout(self):
        """Create a random BTRFS-based configuration"""
        self.log("Creating BTRFS-based layout...")
        self.stats["btrfs"] += 1

        # Pick a random disk
        disk_name = f"disk{random.randint(0, self.config.num_disks - 1)}"
        disk = self.blivet.devicetree.get_device_by_name(disk_name)

        self.log(f"  Using disk: {disk_name} (size: {disk.size})")

        # Initialize the disk
        self.blivet.initialize_disk(disk)

        # Create partition for BTRFS - ensure it fits on disk
        overhead = Size("1 MiB")
        available = disk.size - overhead
        max_size = min(available * 0.95, self.config.max_device_size)
        min_size = self.config.min_device_size

        if max_size < min_size:
            size = max_size
        else:
            min_mb = int(min_size.convert_to("MiB"))
            max_mb = int(max_size.convert_to("MiB"))
            size_mb = random.randint(min_mb, max_mb)
            size = Size(f"{size_mb} MiB")

        part = self.blivet.new_partition(size=size, fmt_type="btrfs")
        self.blivet.create_device(part)

        self.log(f"  Partition: {size}, btrfs")

        # Allocate partition
        try:
            blivet.partitioning.do_partitioning(self.blivet)
        except Exception as e:
            self.log_error(f"  BTRFS partitioning failed! Requested {size} on {disk.size} disk")
            if not self.config.debug_partitioning:
                self.log("  TIP: Run with --debug-partitioning for more details")
            raise

        # Create BTRFS volume
        vol = self.blivet.new_btrfs(parents=[part])
        self.blivet.create_device(vol)
        self.log("  Created BTRFS volume")

        created_devices = [vol]

        # Optionally create subvolumes
        if self.config.btrfs_subvolumes:
            num_subvols = random.randint(1, self.config.max_subvolumes)
            self.log(f"  Creating {num_subvols} subvolume(s)")

            for i in range(num_subvols):
                subvol = self.blivet.new_btrfs_sub_volume(
                    name=f"subvol{i}",
                    parents=[vol]
                )
                self.blivet.create_device(subvol)
                self.log(f"    Subvolume: subvol{i}")
                created_devices.append(subvol)

        return created_devices

    def create_random_stratis_layout(self):
        """Create a random Stratis-based configuration"""
        self.log("Creating Stratis-based layout...")
        self.stats["stratis"] += 1

        # Pick 1-2 disks for block devices
        num_bds = random.randint(1, min(2, self.config.num_disks))
        selected_disks = random.sample(range(self.config.num_disks), num_bds)

        self.log(f"  Using {num_bds} disk(s) for Stratis: {selected_disks}")

        bds = []
        total_bd_size = Size(0)
        for disk_idx in selected_disks:
            disk_name = f"disk{disk_idx}"
            disk = self.blivet.devicetree.get_device_by_name(disk_name)

            # Initialize disk
            self.blivet.initialize_disk(disk)

            # Create partition for Stratis - ensure it fits on disk
            # Use larger block devices for Stratis (2-5 GiB range)
            overhead = Size("1 MiB")
            available = disk.size - overhead
            max_bd_size = min(available * 0.95, Size("5 GiB"))
            min_bd_size = Size("2 GiB")

            if max_bd_size < min_bd_size:
                bd_size = max_bd_size
            else:
                min_gib = int(min_bd_size.convert_to("GiB"))
                max_gib = int(max_bd_size.convert_to("GiB"))
                bd_size = Size(f"{random.randint(min_gib, max_gib)} GiB")

            bd = self.blivet.new_partition(size=bd_size, fmt_type="stratis", parents=[disk])
            self.blivet.create_device(bd)
            bds.append(bd)
            total_bd_size += bd_size
            self.log(f"    Block device on disk{disk_idx}: {bd_size} (disk size: {disk.size})")

        # Allocate partitions
        try:
            blivet.partitioning.do_partitioning(self.blivet)
        except Exception as e:
            self.log_error(f"  Stratis partitioning failed!")
            if not self.config.debug_partitioning:
                self.log("  TIP: Run with --debug-partitioning for more details")
            raise

        # Create Stratis pool
        encrypted = random.random() < self.config.stratis_encrypted_probability

        if encrypted:
            self.log("  Creating encrypted Stratis pool")
            self.stats["encrypted"] += 1
            pool = self.blivet.new_stratis_pool(
                name="fuzz_stratis_pool",
                parents=bds,
                encrypted=True,
                passphrase="test123"
            )
        else:
            self.log("  Creating Stratis pool")
            pool = self.blivet.new_stratis_pool(
                name="fuzz_stratis_pool",
                parents=bds
            )

        self.blivet.create_device(pool)

        # Determine number of filesystems based on pool size
        # Stratis filesystems need ~512 MiB minimum, pool has overhead
        # Be conservative: assume 1 GiB per filesystem + 1 GiB pool overhead
        pool_size_gib = int(total_bd_size.convert_to("GiB"))
        max_filesystems = max(1, (pool_size_gib - 1) // 1)  # At least 1, conservatively
        num_fs = random.randint(1, min(2, max_filesystems))

        self.log(f"  Creating {num_fs} Stratis filesystem(s) (pool size: {total_bd_size})")

        created_devices = []

        for i in range(num_fs):
            try:
                fs = self.blivet.new_stratis_filesystem(
                    name=f"fuzz_stratis_fs{i}",
                    parents=[pool]
                )
                self.blivet.create_device(fs)
                self.log(f"    Filesystem: fuzz_stratis_fs{i}")
                created_devices.append(fs)
            except Exception as e:
                self.log_error(f"    Failed to create filesystem {i}: {e}")
                # If we can't create the filesystem, just use what we have
                break

        if not created_devices:
            raise Exception("Failed to create any Stratis filesystems")

        return created_devices

    def create_random_stacked_layout(self):
        """Create a random stacked layer configuration"""
        self.log("Creating stacked layer configuration...")
        self.stats["stacked"] += 1

        # Generate a random stack
        generator = StackGenerator(self)
        stack = generator.generate_random_stack()

        stack_desc = stack.get_description()
        self.log(f"Stack: {stack_desc}")

        # Get initial devices (disks)
        initial_devices = []
        for i in range(self.config.num_disks):
            disk_name = f"disk{i}"
            disk = self.blivet.devicetree.get_device_by_name(disk_name)
            initial_devices.append(disk)

        # Determine how many disks to use based on whether RAID is in the stack
        # If RAID is present, we need multiple disks so partitions can be created
        # on multiple disks for RAID to use
        has_raid = MDRaidLayer in stack.layers
        if has_raid and self.config.num_disks >= 2:
            # RAID needs multiple partitions from multiple disks
            num_needed = random.randint(2, min(4, self.config.num_disks))
            initial_devices = random.sample(initial_devices, num_needed)
            self.log(f"Using {len(initial_devices)} disks (RAID in stack)")
        else:
            # Use one disk
            initial_devices = [random.choice(initial_devices)]
            self.log(f"Using disk: {initial_devices[0].name}")

        # Create the stack
        try:
            created_devices = stack.create(initial_devices)
            self.log(f"Stack created successfully, {len(created_devices)} final device(s)")
            return created_devices
        except Exception as e:
            self.log_error(f"Stack creation failed: {e}")
            raise

    def build_device_tree(self):
        """Build an ASCII tree representation of the device hierarchy"""
        lines = []
        lines.append("\nStorage Configuration Tree:")
        lines.append("=" * 60)

        # Get all disks used in this iteration
        disks = []
        for i in range(self.config.num_disks):
            disk_name = f"disk{i}"
            disk = self.blivet.devicetree.get_device_by_name(disk_name)
            if disk:
                disks.append(disk)

        # Build tree for each disk
        for disk in disks:
            self._add_device_to_tree(disk, lines, prefix="", is_last=True, is_root=True)

        lines.append("=" * 60)
        return "\n".join(lines)

    def _add_device_to_tree(self, device, lines, prefix="", is_last=True, is_root=False):
        """Recursively add a device and its children to the tree"""
        # Determine the connector
        connector = "└─" if is_last else "├─"

        # Build device info line
        device_info = f"{device.name}"

        # Add size info
        if hasattr(device, 'size') and device.size:
            device_info += f" ({device.size})"

        # Add format info
        if hasattr(device, 'format') and device.format and device.format.type:
            fmt_type = device.format.type
            if fmt_type not in ["disklabel", "partition table", "lvmpv", "mdmember"]:
                device_info += f" [{fmt_type}]"

        # Add the line
        if is_root:  # Root disk - no prefix
            lines.append(device_info)
        else:  # Child device - add prefix and connector
            lines.append(f"{prefix}{connector}{device_info}")

        # Find children of this device
        children = self._get_children(device)

        # Add children recursively
        for idx, child in enumerate(children):
            is_last_child = (idx == len(children) - 1)

            # Update prefix for children
            if is_root:
                # For root level, children start with no prefix
                child_prefix = ""
            else:
                # For nested levels, add spacing based on whether parent is last
                if is_last:
                    child_prefix = prefix + "  "
                else:
                    child_prefix = prefix + "│ "

            self._add_device_to_tree(child, lines, child_prefix, is_last_child, is_root=False)

    def _get_children(self, device):
        """Get direct children of a device in the tree"""
        children = []

        # Iterate through all devices in the tree
        for dev in self.blivet.devicetree.devices:
            # Check if this device has our device as a parent
            if hasattr(dev, 'parents') and device in dev.parents:
                children.append(dev)

        # Sort children by name for consistent output
        children.sort(key=lambda d: d.name)

        return children

    def test_mount_and_write(self, devices):
        """Mount devices and create test files"""
        self.log(f"Testing {len(devices)} device(s) by mounting and writing...")

        # Define which formats are mountable
        mountable_fs = self.config.filesystems + ["btrfs"]

        for i, dev in enumerate(devices):
            # Skip if device doesn't have a mountable filesystem
            if not dev.format:
                self.log(f"  Device {i+1} ({dev.name}): skipping (no format)")
                continue

            # For BTRFS volumes (not subvolumes), skip direct mounting
            if dev.format.type == "btrfs" and not hasattr(dev, 'volume'):
                # This is a BTRFS volume, can be mounted
                pass
            elif dev.format.type == "btrfs" and hasattr(dev, 'volume'):
                # This is a subvolume, skip for now (would need special handling)
                self.log(f"  Device {i+1} ({dev.name}): skipping (BTRFS subvolume)")
                continue
            elif dev.format.type == "stratis":
                # Stratis filesystems are mountable
                pass
            elif dev.format.type not in mountable_fs:
                self.log(f"  Device {i+1} ({dev.name}): skipping (format: {dev.format.type})")
                continue

            # Create temporary mountpoint
            with tempfile.TemporaryDirectory(prefix="fuzz_mount_") as mountpoint:
                try:
                    self.log(f"  Device {i+1} ({dev.name}): mounting at {mountpoint}")
                    dev.format.mount(mountpoint=mountpoint)

                    # Create a test file
                    test_file = os.path.join(mountpoint, "test_file.txt")
                    with open(test_file, 'w') as f:
                        f.write(f"Test data from fuzzer iteration {self.iteration_count}\n")
                        f.write(f"Device: {dev.name}\n")
                        f.write(f"Format: {dev.format.type}\n")

                    # Verify we can read it back
                    with open(test_file, 'r') as f:
                        _content = f.read()

                    self.log(f"  Device {i+1} ({dev.name}): write/read successful")
                    self.stats["mounts_successful"] += 1

                    # Unmount
                    dev.format.unmount()
                    self.log(f"  Device {i+1} ({dev.name}): unmounted")

                except Exception as e:
                    self.log_error(f"  Device {i+1} ({dev.name}): Error during mount/write: {e}", exc_info=True)
                    self.stats["mounts_failed"] += 1
                    raise

    def teardown_configuration(self):
        """Remove all created devices"""
        self.log("Tearing down configuration...")

        try:
            # Reset to get current state
            self.blivet.reset()

            # Remove all devices from our test disks
            for disk_name in [f"disk{i}" for i in range(self.config.num_disks)]:
                disk = self.blivet.devicetree.get_device_by_name(disk_name)
                if disk:
                    self.blivet.recursive_remove(disk)

            # Apply changes
            self.blivet.do_it()

            # Reset again to clear the devicetree cache after removal
            # This prevents stale device references in the next iteration
            self.blivet.reset()

            self.log("Teardown complete")

        except Exception as e:
            self.log_error(f"Teardown error: {e}", exc_info=True)
            raise

    def run_iteration(self):
        """Run one random configuration test"""
        config_type = None
        try:
            # Check for interruption
            if self.interrupted:
                return

            # Choose random configuration type
            config_type = random.choice(self.config.storage_types)

            self.log(f"Configuration type: {config_type}")

            # Create the configuration
            if config_type == "partition":
                devices = self.create_random_partition_layout()
            elif config_type == "lvm":
                devices = self.create_random_lvm_layout()
            elif config_type == "mdraid":
                devices = self.create_random_mdraid_layout()
            elif config_type == "btrfs":
                devices = self.create_random_btrfs_layout()
            elif config_type == "stratis":
                devices = self.create_random_stratis_layout()
            elif config_type == "stacked":
                devices = self.create_random_stacked_layout()
            else:
                raise ValueError(f"Unknown storage type: {config_type}")

            # Check for interruption before applying
            if self.interrupted:
                self.log("Interrupted before applying configuration, cleaning up...")
                self.teardown_configuration()
                return

            # Apply the configuration
            self.log("Applying configuration...")
            self.blivet.do_it()
            self.log("Configuration applied")

            # Display the device tree
            tree = self.build_device_tree()
            print(tree)

            # Check for interruption before testing
            if self.interrupted:
                self.log("Interrupted before testing, tearing down...")
                self.teardown_configuration()
                return

            # Test by mounting and writing
            self.test_mount_and_write(devices)

            # Tear down
            self.teardown_configuration()

            self.success_count += 1
            self.log(">>> Iteration SUCCESSFUL <<<\n")

        except Exception as e:  # pylint: disable=broad-exception-caught
            self.failure_count += 1
            self.log_error(">>> Iteration FAILED <<<", exc_info=True)

            # Save detailed failure info (but not if interrupted)
            if not self.interrupted:
                tb = traceback.format_exc()
                self.save_failure_info(config_type or "unknown", e, tb)

            # Try to clean up anyway
            try:
                self.teardown_configuration()
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    def print_statistics(self):
        """Print detailed statistics"""
        print("\n" + "=" * 70)
        print("DETAILED STATISTICS")
        print("=" * 70)
        print("Configuration types:")
        for stype in ["partition", "lvm", "mdraid", "btrfs", "stratis", "stacked"]:
            count = self.stats.get(stype, 0)
            print(f"  {stype:12s}: {count}")

        print("\nEncryption:")
        print(f"  Encrypted devices: {self.stats.get('encrypted', 0)}")

        print("\nMount operations:")
        print(f"  Successful: {self.stats.get('mounts_successful', 0)}")
        print(f"  Failed: {self.stats.get('mounts_failed', 0)}")

        if self.failures:
            print("\nFailure breakdown:")
            failure_types = defaultdict(int)
            for f in self.failures:
                failure_types[f.config_type] += 1
            for ftype, count in failure_types.items():
                print(f"  {ftype}: {count}")

    def save_summary(self):
        """Save a summary to a JSON file"""
        if not self.config.save_logs:
            return

        actual_iterations = self.success_count + self.failure_count

        summary = {
            "config": self.config.to_dict(),
            "timestamp": datetime.now().isoformat(),
            "requested_iterations": self.config.iterations,
            "completed_iterations": actual_iterations,
            "interrupted": self.interrupted,
            "successful": self.success_count,
            "failed": self.failure_count,
            "success_rate": self.success_count / actual_iterations * 100 if actual_iterations > 0 else 0,
            "statistics": dict(self.stats),
            "failures": [f.to_dict() for f in self.failures]
        }

        summary_file = os.path.join(self.config.log_dir, "summary.json")
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\nSummary saved to: {summary_file}")

    def run(self):
        """Run the fuzzer for specified number of iterations"""
        # Set the random seed for reproducibility
        random.seed(self.config.seed)

        # Set up signal handlers
        self.setup_signal_handlers()

        print("=" * 70)
        print("Blivet Storage Fuzzer")
        print("=" * 70)
        print("Configuration:")
        if self.config.block_devices:
            print(f"  Block devices: {len(self.config.block_devices)}")
            for i, dev in enumerate(self.config.block_devices):
                print(f"    disk{i}: {dev}")
        else:
            print(f"  Disk images: {self.config.num_disks}")
        print(f"  Iterations: {self.config.iterations}")
        print(f"  Random seed: {self.config.seed}")
        print(f"  Storage types: {', '.join(self.config.storage_types)}")
        print(f"  Filesystems: {', '.join(self.config.filesystems)}")
        print(f"  Encryption: {'enabled' if self.config.use_encryption else 'disabled'}")
        if self.config.save_logs:
            print(f"  Logs: {self.config.log_dir}")
        print("=" * 70)
        if self.config.block_devices:
            print("WARNING: All data on the specified block devices will be DESTROYED!")
            print("=" * 70)
        print("Press Ctrl+C to stop and clean up gracefully")
        print("=" * 70)
        print()

        self.iterations = self.config.iterations

        try:
            # Run iterations
            for i in range(1, self.config.iterations + 1):
                # Check for interruption
                if self.interrupted:
                    print("\nStopping after current iteration cleanup...")
                    break

                self.iteration_count = i
                print(f"\n{'=' * 70}")
                print(f"ITERATION {i} of {self.config.iterations}")
                print(f"{'=' * 70}\n")

                # Set up disk images for this iteration
                self.setup_disks()

                try:
                    self.run_iteration()
                finally:
                    # Clean up disk images after each iteration
                    self.cleanup_disks()

                # Check for interruption after iteration
                if self.interrupted:
                    print("\nStopping after iteration cleanup...")
                    break

                # Small delay between iterations
                time.sleep(0.5)

        finally:
            # Final cleanup in case of errors
            if self.disk_files:
                self.cleanup_disks()

            # Restore signal handlers
            self.restore_signal_handlers()

        # Update iterations to actual completed count
        actual_iterations = self.success_count + self.failure_count

        # Print summary
        print("\n" + "=" * 70)
        if self.interrupted:
            print("FUZZING SUMMARY (INTERRUPTED)")
        else:
            print("FUZZING SUMMARY")
        print("=" * 70)
        print(f"Requested iterations: {self.config.iterations}")
        print(f"Completed iterations: {actual_iterations}")
        print(f"Successful: {self.success_count}")
        print(f"Failed: {self.failure_count}")
        if actual_iterations > 0:
            print(f"Success rate: {self.success_count / actual_iterations * 100:.1f}%")
        print("=" * 70)

        # Print detailed statistics
        self.print_statistics()

        # Save summary
        self.save_summary()

        return self.failure_count == 0


def main():
    parser = argparse.ArgumentParser(
        description="Blivet random storage configuration fuzzer (Enhanced)",
        epilog="WARNING: Requires root privileges. Only run on test systems!",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Basic options
    parser.add_argument(
        "-n", "--num-disks",
        type=int,
        default=2,
        help="Number of disk images to create (default: 2, ignored if --block-device is used)"
    )
    parser.add_argument(
        "-b", "--block-device",
        action="append",
        dest="block_devices",
        metavar="DEVICE",
        help="Real block device to use for testing (can be repeated). When specified, "
             "disk images are not created. WARNING: All data on these devices will be destroyed!"
    )
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=10,
        help="Number of random configurations to test (default: 10)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose blivet logging"
    )
    parser.add_argument(
        "--debug-partitioning",
        action="store_true",
        help="Enable extra debugging for partition allocation issues"
    )
    parser.add_argument(
        "--save-logs",
        action="store_true",
        help="Save detailed logs to files"
    )
    parser.add_argument(
        "--log-dir",
        default="/tmp/blivet_fuzzer_logs",
        help="Directory for log files (default: /tmp/blivet_fuzzer_logs)"
    )

    # Storage type filters
    parser.add_argument(
        "--exclude-types",
        nargs="+",
        choices=["partition", "lvm", "mdraid", "btrfs", "stratis", "stacked"],
        help="Exclude specific storage types from testing"
    )
    parser.add_argument(
        "--only-types",
        nargs="+",
        choices=["partition", "lvm", "mdraid", "btrfs", "stratis", "stacked"],
        help="Only test specific storage types"
    )

    # Filesystem options
    parser.add_argument(
        "--filesystems",
        nargs="+",
        choices=["ext4", "ext3", "ext2", "xfs", "vfat"],
        help="Specific filesystems to use (default: all)"
    )

    # Feature toggles
    parser.add_argument(
        "--no-encryption",
        action="store_true",
        help="Disable encryption testing"
    )
    parser.add_argument(
        "--encryption-probability",
        type=float,
        default=0.5,
        help="Probability of encryption (0.0-1.0, default: 0.5)"
    )

    # Reproducibility
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducible runs (default: random)"
    )

    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        print("ERROR: This program requires root privileges!")
        print("Please run with sudo.")
        sys.exit(1)

    # Create configuration
    config = FuzzerConfig()
    config.num_disks = args.num_disks
    config.iterations = args.iterations
    config.verbose = args.verbose
    config.save_logs = args.save_logs
    config.log_dir = args.log_dir
    config.debug_partitioning = args.debug_partitioning

    # Handle block devices
    if args.block_devices:
        config.block_devices = args.block_devices

    # Handle storage type filters
    if args.only_types:
        config.storage_types = args.only_types
    elif args.exclude_types:
        for stype in args.exclude_types:
            config.exclude_storage_type(stype)

    # Handle filesystem options
    if args.filesystems:
        config.set_filesystems(args.filesystems)

    # Handle encryption
    if args.no_encryption:
        config.use_encryption = False
    else:
        config.encryption_probability = args.encryption_probability

    # Handle random seed
    if args.seed is not None:
        config.seed = args.seed
    else:
        # Generate a random seed
        config.seed = random.randint(0, 2**32 - 1)

    # Run the fuzzer
    fuzzer = BlivetFuzzerEnhanced(config)

    success = fuzzer.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
