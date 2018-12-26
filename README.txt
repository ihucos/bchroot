
###########
# bchroot #
###########

- What is bchroot?
bchroot (pronounced beach-root) is a variant of the chroot program.

- Why not just use chroot?
bchroot runs inside Linux namespace, which means that your regular user will be
mapped to root inside the chroot. bchroot also tries to keep parts of the host
operating system by mounting directories like /dev and even /home to the
chroot. There is also an attempt to keep the current working directory inside
the chroot. If the bchroot binary is renamed to a different name, it runs it's
binary name inside any folder called "rootfs" inside it's directory with the
given arguments. This can be useful when distribution software inside a rootfs
or container.

- Current status of the software
Beta
