# Xamarin AssemblyStore Explorer (pyxamstore)

> [!NOTE]
> unpack and repack xamarin assemblies blob from `assemblies.blob` (V1) or payload `libassemblies.<arch>.blob.so` (V2/V3) format.

## Installing
- Using `pip` [recommended]:
```shell
pip install -U git+https://github.com/AbhiTheModder/pyxamstore
```

You can then use the tool by calling `pyxamstore`

## Usage

```shell
$ pyxamstore -h
Pack/unpack Xamarin AssemblyStore payloads.

positional arguments:
  elf_path              Path to the ELF file to operate on; in case of V1 format, it should be path to the assemblies.blob file.
  extracted_dir         Directory created by a previous --unpack/-u (used for --pack/-p); in case of V1 format, it should be path to the assemblies.json
                        (config) file.

options:
  -h, --help            show this help message and exit
  --out-path OUT_PATH, -o OUT_PATH
                        Path for output: when unpacking, directory to place extracted files (default: <elf>_extracted); when packing, path for the
                        re‑packed ELF (default: overwrite original ELF).
  --arch val, -r val    Which architecture to unpack: arm(64), x86(_64) (default: arm64); Only to be used with V1 format. V2 & V3 format doesn't need
                        this
  --unpack, -u          Extract assemblies
  --pack, -p            Re‑pack assemblies
```

### Unpacking
```shell
# V1 format
pyxamstore path/to/assemblies/assemblies.blob -u

# V2/V3 format
pyxamstore path/to/libassemblies.<arch>.blob.so -u
```

Assemblies that are detected as compressed with LZ4 will be automatically decompressed in the extraction process.

### Repacking
```shell
# V1 format
pyxamstore path/to/assemblies/assemblies.json -p

# V2/V3 format
pyxamstore path/to/libassemblies.<arch>.blob.so <extracted_dir> -o path/to/libassemblies.<arch>.blob.so -p
```

# Additional Details
Additional file format details can be found on my [personal website](https://www.thecobraden.com/posts/unpacking_xamarin_assembly_stores/).
