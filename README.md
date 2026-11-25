# oem_unpack

Unpack the vendor firmware packages:

| Vendor | Format | Command |
| --- | --- | --- |
| Huawei | `UPDATE.APP` / `update.bin` | `oem-unpack huawei` |
| LG | `KDZ` / `DZ` | `oem-unpack kdz` |
| Unisoc | `PAC` | `oem-unpack pac` |
| Sony | `SIN` | `oem-unpack sony` |
| OPPO / Realme / OnePlus | `ozip` / `ofp` / `ops` | `oem-unpack oppo` |
| AMLogic | burn image (v1/v2) | `oem-unpack ampack` |
| Rockchip | `RKFW` / `RKAF` | `oem-unpack rkfw` |
| Nokia | `NB0` | `oem-unpack nb0` |

The tool was split out of the vendor page of RNA-ROM. The decryption and the
unpacking are pure Python, no external binary is needed for them.

## What it does and does not do

The unpack produces the partition images of a vendor package, and that is where
it stops. The images themselves are not opened any further: reading an erofs,
an ext4 or a super image needs the external binaries of RNA-ROM, so that step
is left to the main program.

```bash
oem-unpack huawei UPDATE.APP --out ./out
oem-unpack kdz    firmware.kdz --list
oem-unpack kdz    firmware.kdz --out ./out --partition system,super
oem-unpack pac    firmware.pac --out ./ImageFiles
oem-unpack sony   firmware.sin --out ./out
oem-unpack oppo   firmware.ozip --out ./out --rec recovery.img
oem-unpack ampack firmware.img --out ./out
oem-unpack rkfw   firmware.rkfw --out ./out
oem-unpack nb0    firmware.nb0 --out ./out
```

Every message, the help texts and the errors are in English.

## The partition list

Every vendor prints its partitions in the same table, so that the output of the
different formats can be compared at a glance:

```
> Partitions (3):
    #  Name                              Size      Offset
    1  system                         1.0 MiB  0x00001000
    2  super                          2.0 GiB  0x00100000
    3  userdata                     512.0 KiB  0x80100000
```

The columns are the number, the name, the size with a unit and the offset as a
hex number. The size and the offset are left out when the vendor does not
report them, and the AMLogic unpacker adds the type of the entry and its
SHA1.

The table is built by `oem_unpack.listing`, every unpacker uses it:

```python
from oem_unpack import listing

listing.print_partitions([
    {"name": "system", "size": 1024 * 1024, "offset": 0x1000},
])
```

## Install

```bash
pip install -e .
```

The core needs nothing but Python. The OPPO, the Sony and the newer LG DZ
unpackers use `cryptography`, `lz4`, `zstandard` and `pyzstd`, they are
imported lazily:

```bash
pip install -r requirements-all.txt
```

## Options

```
--out DIR          the output directory
--list             only list the partitions, do not extract
--partition NAME   only extract these partitions
```

The KDZ unpacker can also write the metadata that is needed to pack the
firmware again: `--params` writes the `.img.params` of a partition,
`--rawprogram` the `rawprogramN.xml` and `--dz-params` the `.dz.params`.

The OPPO unpacker looks for the AES key of an ozip in the built in table, in a
recovery image (`--rec`) or takes one from the user (`--custom-key`).

## Library use

```python
from oem_unpack import kdzextract

for name, partition, length in kdzextract.list_slices("firmware.kdz"):
    print(name, partition, length)

kdzextract.extract_slices("firmware.kdz", "out", wanted={"system"})
```

## Layout

```
src/oem_unpack/
├── cli.py                        the command line entry
├── log.py                        output and debug logs
├── listing.py                    the shared format of the partition lists
├── gettype.py                    the image and firmware type detection
├── huawei_firmware_extractor.py  Huawei APP / update.bin
├── kdzextract.py                 LG KDZ / DZ
├── pac_extract.py                Unisoc PAC
├── sony_dump.py                  Sony SIN
├── oppo_decrypt.py               OPPO / Realme / OnePlus ozip, ofp, ops
├── ampack.py                     AMLogic
├── rkfw.py                       Rockchip RKFW / RKAF
├── nb0unpack.py                  Nokia NB0
├── logo.py                       the boot logo and splash images
├── rna_aes.py                    the AES stand in for pycryptodome
└── lz4_legacy.py                 the LZ4 legacy decompression
```

## License

MIT, see `LICENSE`.
