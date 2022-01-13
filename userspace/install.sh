# Daca se modifica syscalls.master
cd /sys/kern
make syscalls

# Daca se modifica sys_generic.c
cd /sys/arch/amd64/compile/GENERIC.MP
make obj
make config
make
make install