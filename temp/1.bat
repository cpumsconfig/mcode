python main.py s.m --target=bios

dd if=/dev/zero of=a.img bs=512 count=2880

dd if=out.bin of=a.img bs=512 count=1

qemu-system-i386 -fda a.img

