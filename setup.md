# Running boot for qemu x86

* git clone the folder
* run these commands:
```
cd barrelfish
git checkout minimal
./script.sh
# inside created docker container
mkdir build
cd build
../hake/hake.sh -a x86_64 -s ../
make help-boot
make qemu_x86_64_debug
exit
# Left docker container
cd build
../boot.sh
```
