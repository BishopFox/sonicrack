#!/usr/bin/env python3

import argparse
import hashlib
import io
import gzip
import os
import shutil
import struct
import subprocess
import sys
import tarfile

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# Load previously extracted keys from a directory
def load_keys(dir_path):
    if (
        os.path.isdir(dir_path)
        and os.path.isfile(f"{dir_path}/FW-crypt-release.key")
        and os.path.isfile(f"{dir_path}/SCX-crypt-release.key")
    ):
        try:
            keys = {}
            with open(f"{dir_path}/FW-crypt-release.key") as keyfile:
                keys["fw_crypt_key"] = RSA.importKey(keyfile.read())
            with open(f"{dir_path}/SCX-crypt-release.key") as keyfile:
                keys["scx_crypt_key"] = RSA.importKey(keyfile.read())
            return keys
        except:
            return {}


# Extract SIG image and bootloader from OVA image
def extract_ova_files(image_path):
    # Extract VMDK file
    try:
        vmdk_file = None
        with tarfile.open(image_path, errorlevel=0) as tf:
            for file_name in tf.getnames():
                if file_name.endswith("disk1.vmdk"):
                    tf.extract(file_name, "/tmp/sonicrack", filter="data")
                    vmdk_file = f"/tmp/sonicrack/{os.path.basename(file_name)}"
                    break
    except Exception as err:
        raise ValueError(f"Failed to extract VMDK file from OVA image: {err}")
    if not vmdk_file or not os.path.isfile(vmdk_file):
        raise ValueError("Failed to extract VMDK file from OVA image: not found")

    # Extract volume images from VMDK file with 7zip
    try:
        subprocess.run(
            ["7z", "e", "-o/tmp/sonicrack", vmdk_file, "BOOT.img", "INSTALL-CACHE.img", "ICACHE.img"],
            check=True,
            capture_output=True,
        )
    except Exception as err:
        raise ValueError(f"Failed to extract volume images from VMDK file: {err}")
    if not os.path.isfile("/tmp/sonicrack/BOOT.img"):
        raise ValueError("Failed to extract BOOT.img from VMDK file: not found")
    if os.path.isfile("/tmp/sonicrack/INSTALL-CACHE.img"):
        installer = "INSTALL-CACHE"
    elif os.path.isfile("/tmp/sonicrack/ICACHE.img"):
        installer = "ICACHE"
    else:
        raise ValueError(
            "Failed to extract INSTALL-CACHE.img from VMDK file: not found"
        )

    # Extract bootloader from BOOT volume
    mount_image("/tmp/sonicrack/BOOT.img", "/mnt/BOOT")
    shutil.copy2("/mnt/BOOT/EFI/BOOT/bootx64.efi", "/tmp/sonicrack")
    unmount_image("/mnt/BOOT")

    # Extract firmware image from INSTALL-CACHE volume
    mount_image(f"/tmp/sonicrack/{installer}.img", f"/mnt/{installer}")
    shutil.copy2(
        f"/mnt/{installer}/currentFirmware/currentFirmware.bin.sig", "/tmp/sonicrack"
    )
    unmount_image(f"/mnt/{installer}")

    # Clean up
    os.remove(vmdk_file)
    os.remove("/tmp/sonicrack/BOOT.img")
    os.remove(f"/tmp/sonicrack/{installer}.img")


# Mount volume image
def mount_image(image_path, mount_path):
    if not os.path.isfile(image_path):
        raise ValueError("Failed to load image data: file not found")
    try:
        if not os.path.isdir(mount_path):
            os.makedirs(mount_path)
        subprocess.run(
            ["mount", "-o", "ro", image_path, mount_path],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as err:
        raise ValueError(f"Failed to mount image: {err.stderr.decode().strip()}")
    except Exception as err:
        raise ValueError(f"Failed to mount image: {err}")


# Unmount volume
def unmount_image(mount_path):
    subprocess.run(["umount", mount_path], capture_output=True)
    if os.path.isdir(mount_path):
        shutil.rmtree(mount_path, ignore_errors=True)
    subprocess.run(
        ["cryptsetup", "close", os.path.basename(mount_path)],
        check=False,
        capture_output=True,
    )


# Extract keys from bootloader
def extract_keys(bootloader_path, output_path):
    # Extract initramfs
    extract_initramfs(bootloader_path)
    if not os.path.isfile("/tmp/sonicrack/initramfs.cpio"):
        raise ValueError("Failed to extract initramfs from bootloader")
    os.remove(bootloader_path)

    # Extract encrypted sunup installer and its key from initramfs
    subprocess.run(
        [
            "cpio",
            "-idum",
            "--no-absolute-filenames",
            "--quiet",
            "-F",
            "/tmp/sonicrack/initramfs.cpio",
            "onetime.key",
            "sunup.cpio.gz.enc",
        ],
        cwd="/tmp/sonicrack",
        check=True,
        capture_output=True,
    )
    if not os.path.isfile("/tmp/sonicrack/onetime.key") or not os.path.isfile(
        "/tmp/sonicrack/sunup.cpio.gz.enc"
    ):
        raise ValueError("Failed to extract sunup installer files from initramfs")
    os.remove("/tmp/sonicrack/initramfs.cpio")

    # Decrypt sunup installer
    decrypt_sunup_package(
        "/tmp/sonicrack/sunup.cpio.gz.enc",
        "/tmp/sonicrack/onetime.key",
        "/tmp/sonicrack",
    )
    os.remove("/tmp/sonicrack/onetime.key")
    os.remove("/tmp/sonicrack/sunup.cpio.gz.enc")

    # Decompress sunup installer
    with gzip.open("/tmp/sonicrack/sunup.cpio.gz", "rb") as infile:
        with open("/tmp/sonicrack/sunup.cpio", "wb") as outfile:
            shutil.copyfileobj(infile, outfile)
    if not os.path.isfile("/tmp/sonicrack/sunup.cpio"):
        raise ValueError("Failed to decompress sunup installer package")
    os.remove("/tmp/sonicrack/sunup.cpio.gz")

    # Extract keys from sunup installer
    subprocess.run(
        [
            "cpio",
            "-idum",
            "--no-absolute-filenames",
            "--quiet",
            "-F",
            "/tmp/sonicrack/sunup.cpio",
            "usr/share/installer/FW-crypt-release.key",
            "usr/share/installer/SCX-crypt-release.key",
        ],
        cwd="/tmp/sonicrack",
        check=True,
        capture_output=True,
    )
    if not os.path.isfile(
        "/tmp/sonicrack/usr/share/installer/FW-crypt-release.key"
    ) or not os.path.isfile("/tmp/sonicrack/usr/share/installer/SCX-crypt-release.key"):
        raise ValueError("Failed to extract keys from sunup installer package")
    os.remove("/tmp/sonicrack/sunup.cpio")

    # Copy keys to output directory
    os.makedirs(output_path, exist_ok=True)
    shutil.copy2(
        "/tmp/sonicrack/usr/share/installer/FW-crypt-release.key",
        f"{output_path}/FW-crypt-release.key",
    )
    shutil.copy2(
        "/tmp/sonicrack/usr/share/installer/SCX-crypt-release.key",
        f"{output_path}/SCX-crypt-release.key",
    )
    shutil.rmtree("/tmp/sonicrack/usr")


# Carve initramfs from bootloader
def extract_initramfs(file_path):
    with open(file_path, "rb") as infile:
        bootx = infile.read()
    start = bootx.find(b"\x1f\x8b\x08\x00")
    if start == -1:
        raise ValueError("No initramfs found within bootloader")

    # NOTE: There's no good way to identify the end of the gzip member.
    # We're relying on the presence of 32 null bytes in a row to indicate
    # the end of the stream, but this may not always work.
    end = bootx.find(b"\x00" * 32, start)
    with open("/tmp/sonicrack/initramfs.cpio", "wb") as outfile:
        outfile.write(gzip.decompress(bootx[start:end]))


# Decrypt sunup installer package
def decrypt_sunup_package(file_path, key_path, output_path):
    try:
        subprocess.run(
            [
                "openssl",
                "enc",
                "-a",
                "-d",
                "-aes-256-cbc",
                "-pbkdf2",
                "-in",
                file_path,
                "-out",
                f"{output_path}/sunup.cpio.gz",
                "-pass",
                f"file:{key_path}",
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as err:
        raise ValueError(
            f"Failed to decrypt {file_path}: {err.stderr.decode().strip()}"
        )
    except Exception as err:
        raise ValueError(f"Failed to decrypt {file_path}: {err}")


def read_until(fd, c):
    result = bytearray()
    while 1:
        char = fd.read(1)
        result.extend(char)
        if char == c:
            return bytes(result)


# Extract FW decryption key from SSDH package header
def extract_encrypted_fw_key(fw_image):
    # fwEncryptExtract() from usr/bin/fwDecrypt
    fw_image.seek(1004)  # skip file header
    if fw_image.read(4) != b"\x8f\xc4\xe9\xa7":
        raise ValueError(
            "Failed to extract FW key from image file: invalid magic bytes"
        )
    headerLen, headerRev, headerVer, _, algoKeyId, sskbIndex, rsaKeyLen = struct.unpack(
        ">IBBHIHH", fw_image.read(16)
    )
    if headerLen - rsaKeyLen != 36:
        raise ValueError(
            "Failed to extract FW key from image file: invalid key length value in header"
        )
    iv = fw_image.read(16)
    encrypted_aeskey = fw_image.read(rsaKeyLen)
    return iv, encrypted_aeskey


# Decrypt SW package from SSDH package
def decrypt_sw_package(encrypted_sw_package, scx_crypt_cipher):
    # swpackage_decrypt() from usr/bin/installer
    # Parse SCX key and payload from SW package
    package_file = io.BytesIO(encrypted_sw_package)
    read_until(package_file, b"\n")  # skip over package header
    encrypted_key = package_file.read(256)
    sentinel = get_random_bytes(16)
    key = scx_crypt_cipher.decrypt(encrypted_key, sentinel=sentinel)
    if key == sentinel:
        raise ValueError("Failed to decrypt SCX key")
    password = key.decode().strip() + ":sonicos-release:"
    ciphertext = b"Salted__" + package_file.read()

    # Decrypt payload
    try:
        result = subprocess.run(
            [
                "openssl",
                "enc",
                "-d",
                "-pbkdf2",
                "-aes-256-cbc",
                "-pass",
                f"pass:{password}",
            ],
            input=ciphertext,
            check=True,
            capture_output=True,
            text=False,
        )
    except subprocess.CalledProcessError as err:
        raise ValueError(f"Failed to decrypt SW package: {err.stderr.decode().strip()}")
    except Exception as err:
        raise ValueError(f"Failed to decrypt SW package: {err}")
    return result.stdout


# Load SIG key decryption key from file
def get_crypt_key(file_path):
    try:
        with open(file_path) as keyfile:
            key = RSA.importKey(keyfile.read())
            return key.exportKey("DER").hex()
    except:
        return None


# Helper function for key decryption
def EVP_BytesToKey(password, salt, key_len, iv_len):
    """
    https://stackoverflow.com/questions/13907841/implement-openssl-aes-encryption-in-python
    """
    dtot = hashlib.md5(password + salt).digest()
    d = [dtot]
    while len(dtot) < (iv_len + key_len):
        d.append(hashlib.md5(d[-1] + password + salt).digest())
        dtot += d[-1]
    return dtot[:key_len], dtot[key_len : key_len + iv_len]


# Decrypt SIG-formatted firmware image and extract filesystem image
def decrypt_sig_image(file_path, keys, output_path):
    # Prepare decryption ciphers
    if "fw_crypt_key" not in keys or "scx_crypt_key" not in keys:
        return None
    fw_crypt_cipher = PKCS1_v1_5.new(keys["fw_crypt_key"])
    scx_crypt_cipher = PKCS1_v1_5.new(keys["scx_crypt_key"])

    # Parse FW key and SSDH package from image file
    with open(file_path, "rb") as image_file:
        iv, encrypted_fw_key = extract_encrypted_fw_key(image_file)
        sentinel = get_random_bytes(16)
        fw_key = fw_crypt_cipher.decrypt(
            encrypted_fw_key, sentinel=sentinel, expected_pt_len=16
        )
        if fw_key == sentinel:
            raise ValueError("Failed to decrypt FW key")
        aes_fw_key = AES.new(key=fw_key, mode=AES.MODE_CBC, iv=iv)
        ciphertext = image_file.read()
        if len(ciphertext) & 0xF != 0:
            raise ValueError("Failed to decrypt image file: unaligned ciphertext")

    # Decrypt SSDH package
    plaintext = aes_fw_key.decrypt(ciphertext)
    footer = plaintext[-16:]
    magic, version, datalen, dummy = struct.unpack(">IIII", footer)
    if magic != 0x777DEADB or version != 1 or dummy != 0:
        raise ValueError(
            "Failed to decrypt image file: invalid footer after decryption"
        )
    encrypted_sw_package = plaintext[:datalen]

    # Decrypt and decompress nested SW package
    sw_package = gzip.decompress(
        decrypt_sw_package(encrypted_sw_package, scx_crypt_cipher)
    )

    # Get image file name
    start = sw_package.find(b"FILE=") + 5
    end = sw_package.find(b"\n", start)
    filename = sw_package[start:end].decode()

    # Extract image file (filesystem follows two newlines)
    os.makedirs(output_path, exist_ok=True)
    start = sw_package.find(b"\n\n") + 2
    with open(f"{output_path}/{filename}", "wb") as outfile:
        outfile.write(sw_package[start:])
    return filename


def main():
    # Parse command line arguments
    desc = "A tool to decrypt SonicOSX NSv firmware. Run it against an OVA image first to extract keys, then it can also decrypt SIG images."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        "-k",
        "--keys",
        metavar="KEYS_DIR",
        help="Directory path where keys are stored (defaults to ./keys)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT_DIR",
        help="Directory path where decrypted firmware is saved (defaults to ./)",
    )
    parser.add_argument(
        "IMAGE_PATH",
        help="Path to encrypted firmware image (supported file extensions: .ova, .sig)",
    )
    args = parser.parse_args()

    # Validate firmware image file extension
    if not (args.IMAGE_PATH.endswith(".ova") or args.IMAGE_PATH.endswith(".sig")):
        print("[-] Firmware image format not supported (must be .ova or .sig)")
        sys.exit(1)

    # Determine output directories
    key_path = args.keys if args.keys else f"{os.path.dirname(args.IMAGE_PATH)}/keys"
    output_path = args.output if args.output else os.path.dirname(args.IMAGE_PATH)

    # Load keys from disk if available
    keys = load_keys(key_path)
    if not keys and args.IMAGE_PATH.endswith(".sig"):
        print(
            "[-] Keys must be extracted from an OVA image before a SIG image can be decrypted"
        )
        print(
            "[-] If already extracted, use --keys to indicate the directory where they are saved"
        )
        sys.exit(1)

    # Process firmware
    try:
        # Create temporary directory
        os.makedirs("/tmp/sonicrack", exist_ok=True)

        # Unpack OVA image
        if args.IMAGE_PATH.endswith(".ova"):
            # Extract bootloader and firmware
            print("[*] Extracting files from OVA archive")
            extract_ova_files(args.IMAGE_PATH)
            image_path = "/tmp/sonicrack/currentFirmware.bin.sig"

            # Extract keys from bootloader if needed
            if not keys:
                print("[*] Extracting keys from bootloader")
                extract_keys("/tmp/sonicrack/bootx64.efi", key_path)
                keys = load_keys(key_path)
        else:
            image_path = args.IMAGE_PATH

        # Decrypt SIG image
        print("[*] Decrypting firmware image")
        fw_image = decrypt_sig_image(image_path, keys, output_path)
        print(f"[+] Successfully decrypted {fw_image}")

    except Exception as err:
        print(f"[-] {err}")

    finally:
        # Clean up
        shutil.rmtree("/tmp/sonicrack", ignore_errors=True)


if __name__ == "__main__":
    main()
