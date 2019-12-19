#!/bin/bash

echo "Generating random piece.."
dd if=/dev/urandom of=/mnt/tmpfs/piece.bin bs=4096 count=1

START=date
rounds=384

echo "Encoding piece with AES-256-CBC"
for i in {1..rounds}; do
  openssl enc -aes-256-cbc -in /mnt/tmpfs/piece.ibn -out /mnt/tpmfs/encoding.bin -k 53554250414345 -iv 31303234 -nopad
done

END=date
DIFF=(END - START)/rounds
echo "$rounds"


# echo "Hashing piece"
# openssl dgst -sha256 encoding.bin