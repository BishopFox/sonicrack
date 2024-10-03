# Sonicrack

Developed by Team X at Bishop Fox

## Description

A tool to decrypt SonicOSX NSv firewall firmware (version 7.1.1+). Run it against an OVA image first to extract keys, then it can also decrypt SIG images. Firmware can be obtained from [SonicWall's support site](https://www.mysonicwall.com/muir/ui/workspace/m/feature/download-center) with a valid license.

Keys seem to be specific to each model, so this tool will only work for VMware NSv images. Obtaining keys for other models could, in theory, allow you decrypt other images.

This tool has been made public to support good-faith security research into SonicOSX. For a detailed explanation, visit the [Bishop Fox blog](https://bishopfox.com/blog).

## Setup

Debian Linux:

```
sudo apt update && sudo apt install -y $(awk '{print $1}' requirements/apt.txt)
python3 -m pip install -r requirements/pip.txt
```

Docker:

```
docker build -t sonicrack .
```

## Usage

Debian Linux:

```
$ ./sonicrack.py -h
usage: sonicrack.py [-h] [-k KEYS_DIR] [-o OUTPUT_DIR] IMAGE_PATH

A tool to decrypt SonicOSX NSv firmware. Run it against an OVA image first to extract keys, then it can also decrypt SIG images.

positional arguments:
  IMAGE_PATH            Path to encrypted firmware image (supported file extensions: .ova, .sig)

options:
  -h, --help            show this help message and exit
  -k KEYS_DIR, --keys KEYS_DIR
                        Directory path where keys are stored (defaults to ./keys)
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        Directory path where decrypted firmware is saved (defaults to ./)
```

> NOTE: Run with `sudo` when decrypting OVA images. Elevated privilege is needed to mount volumes.

Docker:

```
docker run -it --rm -v .:/data sonicrack ./sonicrack.py --keys /data/keys --output /data /data/<IMAGE_PATH>
```

> NOTE: Run with `--privileged` when decrypting OVA images. Elevated privilege is needed to mount volumes.

## Examples

Decrypt an OVA image:

```
$ docker run -it --privileged --rm -v .:/data sonicrack ./sonicrack.py --keys /data/keys --output /data /data/nsv-vmware.7.1.1-7047-R5557.ova
[*] Extracting files from OVA archive
[*] Extracting keys from bootloader
[*] Decrypting firmware image
[+] Successfully decrypted soniccorex-image-release-nsv-vmware-20240205204943.rootfs.ext4
```

Decrypt a SIG image after extracting keys from an OVA image:

```
$ docker run -it --rm -v .:/data sonicrack ./sonicrack.py --keys /data/keys --output /data /data/sw_nsv_vmware_eng.7.1.2-7019-R6288.bin.sig
[*] Decrypting firmware image
[+] Successfully decrypted soniccorex-image-release-nsv-vmware-20240709184216.rootfs.ext4
```

Attempting to decrypt a SIG image before extracting keys will not work:

```
$ docker run -it --rm -v .:/data sonicrack ./sonicrack.py --keys /data/keys --output /data /data/sw_nsv_vmware_eng.7.1.2-7019-R6288.bin.sig
[-] Keys must be extracted from an OVA image before a SIG image can be decrypted
[-] If already extracted, use --keys to indicate the directory where they are saved
```

Attempting to decrypt an image for a different model will not work:

```
$ docker run -it --rm -v .:/data sonicrack ./sonicrack.py --keys /data/keys --output /data /data/sw_nsa_6700_eng.7.1.2-7019-R6288.bin.sig
[*] Decrypting firmware image
[-] Failed to decrypt FW key
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
