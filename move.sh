#!/bin/sh

# Create folder in tmp
echo "[*] Creating Folder in /tmp"
mkdir -p /tmp/p970_kernel
echo "[*] Folder created: /tmp/p970_kernel"
echo "-"
# Copy Modules
echo "[*] Copying wireless.ko from drivers/net/wireless/bcm43291/wireless.ko"
cp drivers/net/wireless/bcm43291/wireless.ko /tmp/p970_kernel
echo "[*] Copying scsi_wait_scan.ko from drivers/scsi/scsi_wait_scan.ko"
cp drivers/scsi/scsi_wait_scan.ko /tmp/p970_kernel
echo "-"
echo "[*] Modules copied!"
echo "-"
echo "[*] Copying boot.img from arch/arm/boot/zImage"
cp arch/arm/boot/zImage /tmp/p970_kernel
echo "-"
echo "[*] All Done!"
