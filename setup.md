# Running boot for qemu x86

* git clone the folder
* run these commands:
```
cd barrelfish
git checkout minimal
mkdir build
cd build
./script.sh
# inside created docker container
../hake/hake.sh -a x86_64 -s ../ # only the first time
make help-boot
make qemu_x86_64_debug
exit
# Left docker container
cd build
../boot.sh
```

## Current state:
 * script.sh builds inside the container and leaves automatically.
 TODO: Update it to also automate hake command
