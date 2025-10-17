#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# @author: Abhi (@AbhiTheModder)

"""Pack and unpack Xamarin AssemblyStore files"""

import argparse
import json
import os
import pathlib
import struct
import sys

import lz4.block as lz4
from elftools.elf.elffile import ELFFile

from .v1 import do_pack, do_unpack


# https://github.com/dotnet/android/blob/04340244c3cb1753a987b6809a91631dc883b035/tools/assembly-store-reader-mk2/AssemblyStore/StoreReader_V2.Classes.cs#L21
class Header:
    """
    Header of AssemblyStore
    """

    def __init__(self, data):
        (
            self.magic,
            self.version,
            self.entry_count,
            self.index_entry_count,
            self.index_size,
        ) = struct.unpack("<5I", data)


# https://github.com/dotnet/android/blob/04340244c3cb1753a987b6809a91631dc883b035/tools/assembly-store-reader-mk2/AssemblyStore/StoreReader_V2.Classes.cs#L31
# V3 change: https://github.com/dotnet/android/commit/aac59125f4f21002ade246f25eb2daaeb7909eda
class IndexEntry:
    """
    Index entry of AssemblyStore
    """

    def __init__(self, data, is64Bit, version):
        self.ignore = False
        if version == 2:
            if is64Bit:
                self.name_hash, self.descriptor_index = struct.unpack("<QI", data)
            else:
                self.name_hash, self.descriptor_index = struct.unpack("<II", data)
        elif version == 3:
            if is64Bit:
                self.name_hash, self.descriptor_index, ignore_byte = struct.unpack(
                    "<QIB", data
                )
            else:
                self.name_hash, self.descriptor_index, ignore_byte = struct.unpack(
                    "<IIB", data
                )
            self.ignore = ignore_byte != 0
        else:
            raise ValueError(f"Unsupported AssemblyStore version: {version}")


# https://github.com/dotnet/android/blob/04340244c3cb1753a987b6809a91631dc883b035/tools/assembly-store-reader-mk2/AssemblyStore/StoreReader_V2.Classes.cs#L43
class EntryDescriptor:
    """
    Entry descriptor of AssemblyStore
    """

    def __init__(self, data):
        (
            self.mapping_index,
            self.data_offset,
            self.data_size,
            self.debug_data_offset,
            self.debug_data_size,
            self.config_data_offset,
            self.config_data_size,
        ) = struct.unpack("<7I", data)


def extract_payload(elf_path, output_file_path):
    """
    Extract payload from ELF file
    """

    with open(elf_path, "rb") as elf_file:
        elf = ELFFile(elf_file)
        payload = elf.get_section_by_name("payload")
        if payload is None:
            print("No .payload section found")
            exit(1)
        if elf.header.e_machine == "EM_AARCH64":
            is64Bit = True
        elif elf.header.e_machine == "EM_ARM":
            is64Bit = False
        else:
            print("Unsupported architecture")  # For now
            exit(1)
        payload_data = payload.data()
        with open(output_file_path, "wb") as output_file:
            output_file.write(payload_data)
        return is64Bit


def extract_assemblies(payload_path, is64Bit, version):
    """
    Extract assemblies from payload
    """

    with open(payload_path, "rb") as payload_file:
        # Read the header
        header_data = payload_file.read(20)
        header = Header(header_data)

        index_entries = []
        for _ in range(header.index_entry_count):
            if version == 2:
                entry_size = 12 if is64Bit else 8
            elif version == 3:
                entry_size = 13 if is64Bit else 9
            else:
                raise ValueError(f"Unsupported AssemblyStore version: {version}")

            index_entry_data = payload_file.read(entry_size)
            index_entry = IndexEntry(index_entry_data, is64Bit, version)
            index_entries.append(index_entry)

        entry_descriptors = []
        for _ in range(header.entry_count):
            entry_descriptor_data = payload_file.read(28)
            entry_descriptor = EntryDescriptor(entry_descriptor_data)
            entry_descriptors.append(entry_descriptor)

        assembly_names = []
        for _ in range(header.entry_count):
            name_length_data = payload_file.read(4)
            name_length = struct.unpack("<I", name_length_data)[0]
            name_data = payload_file.read(name_length)
            assembly_names.append(name_data.decode("utf-8"))

        assemblies = []
        descriptor_indices = []

        for descriptor in entry_descriptors:
            if descriptor.data_size == 0:
                assemblies.append(b"")
                descriptor_indices.append(None)
                continue

            payload_file.seek(descriptor.data_offset)
            assembly_data = payload_file.read(descriptor.data_size)
            # print(descriptor.data_size, descriptor.data_offset)

            desc_idx = None
            # Unpack if LZ4 compressed
            if assembly_data[:4] == b"XALZ":
                desc_idx = struct.unpack("<I", assembly_data[4:8])[0]
                packed_payload_len = struct.unpack("<I", assembly_data[8:12])[0]
                compressed_payload = assembly_data[12:]
                assembly_data = lz4.decompress(
                    compressed_payload, uncompressed_size=packed_payload_len
                )

            assemblies.append(assembly_data)
            descriptor_indices.append(desc_idx)

        return (
            assemblies,
            entry_descriptors,
            index_entries,
            descriptor_indices,
            assembly_names,
        )


def lz4_compress(file_data, desc_idx):
    """LZ4 compress data stream + add header"""

    packed = struct.pack("4sII", b"XALZ", desc_idx, len(file_data))
    # Previously compression level was 9, https://github.com/AbhiTheModder/pyxamstore/blob/843b00da86ddee8a05541f63b1fd6855634a77bc/pyxamstore/__init__.py#L349
    # Now it's 12
    # see https://github.com/dotnet/android/blob/04340244c3cb1753a987b6809a91631dc883b035/src/Xamarin.Android.Build.Tasks/Utilities/AssemblyCompression.cs#L89
    compressed_data = lz4.compress(
        file_data, mode="high_compression", store_size=False, compression=12
    )
    packed += compressed_data
    return packed


def pack_elf(elf_path, payload_path, output_elf_path):
    """
    Pack payload into ELF
    """
    if not output_elf_path:
        output_elf_path = elf_path
    with open(elf_path, "rb") as elf_file:
        elf_data = elf_file.read()
        elf = ELFFile(elf_file)
        if elf.header.e_machine == "EM_AARCH64":
            is64Bit = True
        elif elf.header.e_machine == "EM_ARM":
            is64Bit = False
        else:
            raise ValueError("Unsupported ELF architecture")

    with open(payload_path, "rb") as payload_file:
        payload_data = payload_file.read()

    elf_header = elf_data[:64]
    if is64Bit:
        e_shoff = struct.unpack_from("<Q", elf_header, 40)[0]
        e_shnum = struct.unpack_from("<H", elf_header, 60)[0]
        e_shentsize = struct.unpack_from("<H", elf_header, 58)[0]
        e_shstrndx = struct.unpack_from("<H", elf_header, 62)[0]
    else:
        e_shoff = struct.unpack_from("<I", elf_header, 32)[0]
        e_shnum = struct.unpack_from("<H", elf_header, 48)[0]
        e_shentsize = struct.unpack_from("<H", elf_header, 46)[0]
        e_shstrndx = struct.unpack_from("<H", elf_header, 50)[0]

    section_headers = elf_data[e_shoff : e_shoff + e_shnum * e_shentsize]
    if is64Bit:
        shstrtab_offset = struct.unpack_from(
            "<Q", section_headers, e_shstrndx * e_shentsize + 24
        )[0]
        shstrtab_size = struct.unpack_from(
            "<Q", section_headers, e_shstrndx * e_shentsize + 32
        )[0]
    else:
        shstrtab_offset = struct.unpack_from(
            "<I", section_headers, e_shstrndx * e_shentsize + 16
        )[0]
        shstrtab_size = struct.unpack_from(
            "<I", section_headers, e_shstrndx * e_shentsize + 20
        )[0]
    shstrtab = elf_data[shstrtab_offset : shstrtab_offset + shstrtab_size]

    payload_offset = None
    payload_size = None
    for i in range(e_shnum):
        sh_name_offset = struct.unpack_from("<I", section_headers, i * e_shentsize + 0)[
            0
        ]
        section_name = shstrtab[sh_name_offset:].split(b"\x00", 1)[0]
        if section_name == b"payload":
            if is64Bit:
                payload_offset = struct.unpack_from(
                    "<Q", section_headers, i * e_shentsize + 24
                )[0]
                payload_size = struct.unpack_from(
                    "<Q", section_headers, i * e_shentsize + 32
                )[0]
            else:
                payload_offset = struct.unpack_from(
                    "<I", section_headers, i * e_shentsize + 16
                )[0]
                payload_size = struct.unpack_from(
                    "<I", section_headers, i * e_shentsize + 20
                )[0]
            break

    if payload_offset is None or payload_size is None:
        raise ValueError("Payload section not found in the ELF file")

    new_elf_data = (
        elf_data[:payload_offset]
        + payload_data
        + elf_data[payload_offset + payload_size :]
    )

    with open(output_elf_path, "wb") as output_file:
        output_file.write(new_elf_data)


def update_payload(config_file, payload_path, assembly_folder):
    """
    Update payload with assemblies from assembly_folder
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)

        with open(payload_path, "r+b") as payload:
            for assembly, info in config.items():
                if info.get("ignored", False):
                    print(f"Skipping ignored assembly: {assembly}")
                    continue

                assembly_path = os.path.join(assembly_folder, assembly)

                if not os.path.exists(assembly_path):
                    print(f"Warning: {assembly_path} does not exist. Skipping...")
                    continue

                with open(assembly_path, "rb") as asm_file:
                    assembly_data = asm_file.read()
                    if assembly_data[:2] == b"MZ":
                        compressed_data = lz4_compress(assembly_data, info["idx"])
                        assembly_data = compressed_data
                    elif assembly_data[:4] == b"XALZ":
                        pass
                    else:
                        print(
                            f"Error: {assembly} is not a valid PE or XALZ file. Skipping."
                        )
                        continue

                # Size shouldn't change much else xamarin will crash with an
                # Abort message:'Compressed assembly
                # '<assembly_store>' is larger than when the
                # application was built (expected at most 2560, got
                # 1893376). Assemblies don't grow just like that!'
                # TODO: Maybe support upto some size ?
                if len(assembly_data) > info["size"]:
                    print(f"Error: {assembly} exceeds the allocated size. Skipping.")
                    continue

                payload.seek(info["offset"])

                payload.write(assembly_data)
                print(f"{assembly} updated in {payload_path}.")

    except Exception as e:
        print(f"An error occurred: {e}")


def unpack_payload(payload_path: str, assembly_out: str, arch: str | None = None):
    print("Verifying payload...")
    with open(payload_path, "rb") as payload_file:
        header_data = payload_file.read(20)
        if header_data[:4] != b"XABA":
            raise ValueError("Payload is not valid!")

        print("Payload is valid!")
        header = Header(header_data)

        # The base version (2 or 3) is in the lowest byte.
        version = header.version & 0xFF
        is64Bit = (header.version & 0x80000000) != 0

        if version not in [1, 2, 3]:
            raise ValueError(f"Unsupported AssemblyStore version: {version}")

    if version == 1:
        print(f"Detected AssemblyStore v{version}.")
        payload_dir = os.path.dirname(payload_path)
        do_unpack(payload_dir, arch, True)
    else:
        print(
            f"Detected AssemblyStore v{version} for {'64-bit' if is64Bit else '32-bit'} architecture."
        )
        (
            assemblies,
            entry_descriptors,
            index_entries,
            descriptor_indices,
            assembly_names,
        ) = extract_assemblies(payload_path, is64Bit, version)

        is_ignored_map = {}
        for entry in index_entries:
            is_ignored_map[entry.descriptor_index] = entry.ignore

        config_data = {}
        for i, (assembly, descriptor, desc_idx, real_name) in enumerate(
            zip(assemblies, entry_descriptors, descriptor_indices, assembly_names)
        ):
            assembly_name = real_name if real_name else f"assembly_{i}.dll"
            ignored = is_ignored_map.get(i, False)

            if not ignored and assembly:
                dest_path = os.path.join(assembly_out, assembly_name)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, "wb") as assembly_file:
                    assembly_file.write(assembly)

            idx_to_store = (
                desc_idx if desc_idx is not None else descriptor.mapping_index
            )
            config_data[assembly_name] = {
                "idx": idx_to_store,
                "offset": descriptor.data_offset,
                "size": descriptor.data_size,
                "ignored": ignored,
            }
        with open(
            os.path.join(assembly_out, "assembly_config.json"), "w"
        ) as config_json:
            json.dump(config_data, config_json, indent=4)

    print("Assemblies extracted successfully!")
    return


def unpack_elf(
    elf_path: pathlib.Path, out_dir: None | pathlib.Path = None, arch: str | None = None
):
    """
    Function to unpack and extract payload & assemblies from an ELF file
    """
    if not out_dir:
        out_dir = elf_path.with_name(f"{elf_path.stem}_extracted")

    payload_path = out_dir / "payload.bin"
    assembly_out = out_dir / "out"

    if elf_path.name.endswith(".blob"):
        payload_path = elf_path
    else:
        os.makedirs(assembly_out, exist_ok=True)
        extract_payload(str(elf_path), str(payload_path))
        print(f"Payload extracted to {payload_path}")

    unpack_payload(str(payload_path), str(assembly_out), arch)

    return out_dir


def main():
    parser = argparse.ArgumentParser(
        description="Pack/unpack Xamarin AssemblyStore payloads."
    )
    parser.add_argument(
        "elf_path",
        help="Path to the ELF file to operate on; in case of V1 format, it should be path to the assemblies.blob file.",
    )
    parser.add_argument(
        "extracted_dir",
        nargs="?",
        help="Directory created by a previous --unpack/-u (used for --pack/-p); in case of V1 format, it should be path to the assemblies.json (config) file.",
    )
    parser.add_argument(
        "--out-path",
        "-o",
        help=(
            "Path for output: when unpacking, directory to place extracted files "
            "(default: <elf>_extracted); when packing, path for the re‑packed ELF "
            "(default: overwrite original ELF)."
        ),
    )
    parser.add_argument(
        "--arch",
        "-r",
        type=str,
        metavar="val",
        default="arm64",
        help="Which architecture to unpack: arm(64), x86(_64) (default: arm64); Only to be used with V1 format. V2 & V3 format doesn't need this",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--unpack", "-u", action="store_true", help="Extract assemblies")
    group.add_argument(
        "--pack",
        "-p",
        action="store_true",
        help="Re‑pack assemblies",
    )

    args = parser.parse_args()
    out_path = pathlib.Path(args.out_path) if args.out_path else None

    if args.unpack:
        elf_path = pathlib.Path(args.elf_path)
        unpack_dir = unpack_elf(elf_path, out_path, args.arch)
        print(f"All files placed in: {unpack_dir}")

    elif args.pack:
        if not args.extracted_dir:
            parser.error("--pack/-p requires the extracted directory argument")
        extracted_path = pathlib.Path(args.extracted_dir)

        if str(args.elf_path).endswith(".blob"):
            with open(args.elf_path, "rb") as payload_file:
                header_data = payload_file.read(20)
                if header_data[:4] != b"XABA":
                    raise ValueError("blob is not valid!")

                header = Header(header_data)
                version = header.version & 0xFF
            if version == 1:
                if not extracted_path.name.endswith(".json"):
                    exit("extracted_path must be the path to config path for V1 format")
                do_pack(str(extracted_path))
                return

        payload_path = extracted_path / "payload.bin"
        config_path = extracted_path / "out" / "assembly_config.json"
        assembly_folder = extracted_path / "out"

        if not payload_path.is_file() or not config_path.is_file():
            sys.exit(
                f"Missing payload or config in {extracted_path}. "
                "Run the tool with --unpack/-u first."
            )

        update_payload(str(config_path), str(payload_path), str(assembly_folder))

        pack_elf(args.elf_path, str(payload_path), str(out_path))
        print(f"Re‑packed ELF written to {out_path}")


if __name__ == "__main__":
    main()
