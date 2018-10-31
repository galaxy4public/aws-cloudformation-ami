#!/bin/bash
TARGET_VOL="${TARGET_VOL:-}"
AMI_NAME_TAG="${AMI_NAME_TAG:-}"
BOOTSTRAP_MNT="/mnt/bootstrap"
AWS_TIMEOUT=30 # minutes (in reality no operation should take more than 10)

LC_ALL=C
LANG=C
export BOOTSTRAP_MNT LC_ALL LANG

if [ -n "$cfnSignalURL" ]; then
	error_handler()
	{
		local RC=$?
		local CHAIN_SIZE="$1"
		local ERROR_CHAIN=
		local I
		set +e
		trap - ERR HUP INT QUIT TERM KILL ABRT SEGV EXIT
		for ((I=${CHAIN_SIZE:-0}; I > 0; I--)); do
			ERROR_CHAIN="$ERROR_CHAIN${BASH_SOURCE[$((CHAIN_SIZE-I+1))]}:${BASH_LINENO[$((CHAIN_SIZE-I))]}"
			[ $I -gt 1 ] && ERROR_CHAIN="$ERROR_CHAIN < " ||:
		done
		[ "$CHAIN_SIZE" == 0 -a -z "$ERROR_CHAIN" ] && ERROR_CHAIN="line $LINENO" ||:
		curl -X PUT -H 'Content-Type:' \
			--data-binary '{ "Status": "FAILURE", "Reason": "Bootstrap FAILED at '"$ERROR_CHAIN"'", "UniqueId": "Log", "Data": "Failure" }' "$cfnSignalURL"; \
		exit $RC
	}

	trap 'error_handler "${#BASH_LINENO[@]}"' ERR HUP INT QUIT TERM KILL ABRT SEGV EXIT
fi
set -exu -o pipefail

# XXX: before we do anything else we need to verify that we are running
# in a proper environment -- our only requirement at this stage is to
# have Internet connectivity.  One of the options to check for this is
# to test whether we have the default route configured or not.
if ! ping -q -c 3 8.8.8.8 >/dev/null ; then
	echo "ERROR: failed to confirm the Internet connectivity" >&2
	exit 1
fi

if [ -z "${TARGET_VOL:-}" ]; then
	# No target volume has been specified, let's try to guess.
	if [ -b /dev/nvme1n1 ]; then
		# we are running on a new type of instances where EBS
		# volumes are attached as NVMe devices
		TARGET_VOL=/dev/nvme1n1
	elif [ -b /dev/xvdf ]; then
		# looks like an old type of an instance
		TARGET_VOL=/dev/xvdf
	else
		echo "ERROR: failed to detect the target volume, please explicitly specify one as an argument to the script!" >&2
		exit 1
	fi
fi

# Since we may work with either NVMe or legacy block devices we need to
# accomodate for their different naming conventions.
P=''
[ "${TARGET_VOL:0:9}" == /dev/nvme ] && P=p || :

# This is an optional but very nice to have step (the downside is it takes time)
#dd if=/dev/zero of="$TARGET_VOL" bs=100M || :

sfdisk "$TARGET_VOL" << "__EOF__"
unit: sectors

2048,,83,*
__EOF__

I=0
until dd "if=${TARGET_VOL}${P:-}1" of=/dev/null bs=1 count=1 >/dev/null 2>/dev/null ; do
	# if we don't get the device in 3 minutes, bail out
	if [ $I -ge 180 ]; then
		echo "ERROR: failed to acquire '${TARGET_VOL}${P:-}1'!" >&2
		exit 1
	fi
	sleep 1;
	I=$((I + 1))
done
unset I

mkfs -F -t ext4 -E lazy_itable_init=0,lazy_journal_init=0 -M / -q \
	"${TARGET_VOL}${P:-}1"

# We are using tune2fs and sed here so we do not introduce additional
# dependencies on blkid and grep for no particular reason
FS_UUID=$(tune2fs -l "${TARGET_VOL}${P:-}1" \
	| sed -n 's,^\s*Filesystem\s\+UUID:\s*\([a-f0-9-]\+\),\1,;T;p' \
	| tail -1 \
)

mkdir -p -m0 "$BOOTSTRAP_MNT"
mount "${TARGET_VOL}${P:-}1" "$BOOTSTRAP_MNT"
touch "$BOOTSTRAP_MNT"/.autorelabel

cat > /root/centos7.gpg << "__EOF__"
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.5 (GNU/Linux)

mQINBFOn/0sBEADLDyZ+DQHkcTHDQSE0a0B2iYAEXwpPvs67cJ4tmhe/iMOyVMh9
Yw/vBIF8scm6T/vPN5fopsKiW9UsAhGKg0epC6y5ed+NAUHTEa6pSOdo7CyFDwtn
4HF61Esyb4gzPT6QiSr0zvdTtgYBRZjAEPFVu3Dio0oZ5UQZ7fzdZfeixMQ8VMTQ
4y4x5vik9B+cqmGiq9AW71ixlDYVWasgR093fXiD9NLT4DTtK+KLGYNjJ8eMRqfZ
Ws7g7C+9aEGHfsGZ/SxLOumx/GfiTloal0dnq8TC7XQ/JuNdB9qjoXzRF+faDUsj
WuvNSQEqUXW1dzJjBvroEvgTdfCJfRpIgOrc256qvDMp1SxchMFltPlo5mbSMKu1
x1p4UkAzx543meMlRXOgx2/hnBm6H6L0FsSyDS6P224yF+30eeODD4Ju4BCyQ0jO
IpUxmUnApo/m0eRelI6TRl7jK6aGqSYUNhFBuFxSPKgKYBpFhVzRM63Jsvib82rY
438q3sIOUdxZY6pvMOWRkdUVoz7WBExTdx5NtGX4kdW5QtcQHM+2kht6sBnJsvcB
JYcYIwAUeA5vdRfwLKuZn6SgAUKdgeOtuf+cPR3/E68LZr784SlokiHLtQkfk98j
NXm6fJjXwJvwiM2IiFyg8aUwEEDX5U+QOCA0wYrgUQ/h8iathvBJKSc9jQARAQAB
tEJDZW50T1MtNyBLZXkgKENlbnRPUyA3IE9mZmljaWFsIFNpZ25pbmcgS2V5KSA8
c2VjdXJpdHlAY2VudG9zLm9yZz6JAjUEEwECAB8FAlOn/0sCGwMGCwkIBwMCBBUC
CAMDFgIBAh4BAheAAAoJECTGqKf0qA61TN0P/2730Th8cM+d1pEON7n0F1YiyxqG
QzwpC2Fhr2UIsXpi/lWTXIG6AlRvrajjFhw9HktYjlF4oMG032SnI0XPdmrN29lL
F+ee1ANdyvtkw4mMu2yQweVxU7Ku4oATPBvWRv+6pCQPTOMe5xPG0ZPjPGNiJ0xw
4Ns+f5Q6Gqm927oHXpylUQEmuHKsCp3dK/kZaxJOXsmq6syY1gbrLj2Anq0iWWP4
Tq8WMktUrTcc+zQ2pFR7ovEihK0Rvhmk6/N4+4JwAGijfhejxwNX8T6PCuYs5Jiv
hQvsI9FdIIlTP4XhFZ4N9ndnEwA4AH7tNBsmB3HEbLqUSmu2Rr8hGiT2Plc4Y9AO
aliW1kOMsZFYrX39krfRk2n2NXvieQJ/lw318gSGR67uckkz2ZekbCEpj/0mnHWD
3R6V7m95R6UYqjcw++Q5CtZ2tzmxomZTf42IGIKBbSVmIS75WY+cBULUx3PcZYHD
ZqAbB0Dl4MbdEH61kOI8EbN/TLl1i077r+9LXR1mOnlC3GLD03+XfY8eEBQf7137
YSMiW5r/5xwQk7xEcKlbZdmUJp3ZDTQBXT06vavvp3jlkqqH9QOE8ViZZ6aKQLqv
pL+4bs52jzuGwTMT7gOR5MzD+vT0fVS7Xm8MjOxvZgbHsAgzyFGlI1ggUQmU7lu3
uPNL0eRx4S1G4Jn5
=OGYX
-----END PGP PUBLIC KEY BLOCK-----
__EOF__

cat > /root/yum.conf << "__EOF__"
[main]
cachedir=/var/cache/yum/$basearch/7
keepcache=0
logfile=/dev/null
exactarch=1
obsoletes=1
gpgcheck=1
plugins=0
distroverpkg=centos-release
reposdir=/dev/null
protected_packages=
tsflags=nodocs
override_install_langs=(none)
deltarpm=0
clean_requirements_on_remove=1
usr_w_check=0

[base]
name=CentOS-7 - Base
mirrorlist=http://mirrorlist.centos.org/?release=7&arch=$basearch&repo=os&infra=$infra
gpgkey=file:///root/centos7.gpg

[updates]
name=CentOS-7 - Updates
mirrorlist=http://mirrorlist.centos.org/?release=7&arch=$basearch&repo=updates&infra=$infra
gpgkey=file:///root/centos7.gpg
__EOF__

cat > ~/.rpmmacros << "__EOF__"
%_install_langs (none)
%_netsharedpath %_datadir/locale:%__docdir_path
%_excludedocs 1
__EOF__

mkdir -p -m755 "$BOOTSTRAP_MNT"/dev
mknod -m 0600 "$BOOTSTRAP_MNT"/dev/console c 5 1
mknod -m 0600 "$BOOTSTRAP_MNT"/dev/kmsg c 1 11
mknod -m 0666 "$BOOTSTRAP_MNT"/dev/null c 1 3
mknod -m 0666 "$BOOTSTRAP_MNT"/dev/full c 1 7
mknod -m 0666 "$BOOTSTRAP_MNT"/dev/zero c 1 5
mknod -m 0666 "$BOOTSTRAP_MNT"/dev/random c 1 8
mknod -m 0666 "$BOOTSTRAP_MNT"/dev/urandom c 1 9

safe_yum()
{
	# Sometimes we hit a bad mirror and yum fails with a timeout message, so
	# let's try three times
	I=0
	until yum -y --noplugins -c /root/yum.conf \
			--disablerepo=* --enablerepo=base,updates \
			--installroot="$BOOTSTRAP_MNT" \
			"$@"
	do
		RC=$?
		if [ $I -ge 2 ]; then
			echo "ERROR: yum failed 3 times with error code '$RC'!" >&2
			exit $RC
		fi
		echo "NOTICE: yum failed with error code '$RC', re-trying ..." >&2
		I=$(( I + 1 ))
	done
	unset I
}

safe_yum install \
	basesystem grub2 kernel dracut e2fsprogs yum \
	yum-plugin-post-transaction-actions attr patch \
	dhclient openssh-server selinux-policy-targeted \
	less vim-minimal policycoreutils-python audit \
	systemd-networkd systemd-resolved

safe_yum remove \
	initscripts systemd-sysv

cat > "$BOOTSTRAP_MNT"/etc/rpm/macros.local << "__EOF__"
%_install_langs (none)
%_netsharedpath %_datadir/locale:%__docdir_path
%_excludedocs 1
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/rpm/macros.local

SCRIPT_CHECKSUM=$(sha256sum "${BASH_SOURCE[0]}" | cut -f1 -d' ')
DISTRO_RELEASE=$(chroot "$BOOTSTRAP_MNT" /bin/sh -c "rpm -q centos-release | sed -n 's,^centos-release-\([[:digit:].-]\+\)\.el.*,\1,;T;s,-,.,;p'")

# It was discovered that "rpm" was failing silently (with exit code 0)
# when /dev/urandom was not available.  This resulted in the wrong
# image checksum being calculated, so to somewhat protect ourselves
# we are checking for the DISTRO_RELEASE being populated.
if [ -z "$DISTRO_RELEASE" ]; then
	echo "ERROR: the DISTRO_RELEASE variable is empty, most likely RPM inside the chroot is playing out!" >&2
	exit 2
fi

IMAGE_CHECKSUM=$(chroot "$BOOTSTRAP_MNT" /bin/sh -c "rpm -qa | LC_ALL=C sort | sha256sum | cut -f1 -d' '")

# Compatibility with the previous versions
if [ -s /root/bootstrap-addon.sh ]; then
	mkdir -p -m700 /root/bootstrap.d
	mv /root/bootstrap-addon.sh /root/bootstrap.d/99-custom-user-data.sh
fi

# If custom user data was provided add its hash to the image checksum
if [ "$(echo /root/bootstrap.d/*)" != '/root/bootstrap.d/*' ]; then
	IMAGE_CHECKSUM="$IMAGE_CHECKSUM:$(cat $(ls -1a /root/bootstrap.d/* | LC_ALL=C sort) | sha256sum | cut -f1 -d' ')"
fi

AMI_ID=$(aws ec2 describe-images --output json \
		--owners self \
		--filters \
			Name=state,Values=available \
			"Name=architecture,Values=$(uname -m | sed 's,i.86,i386,')" \
			"Name=tag:image/distro,Values=CentOS" \
			"Name=tag:image/distro/release,Values=$DISTRO_RELEASE" \
			"Name=tag:image/checksum,Values=$IMAGE_CHECKSUM" \
			"Name=tag:image/checksum/script,Values=$SCRIPT_CHECKSUM" \
			| sed -n '/"ImageId"[[:space:]]*:/s,^.*"ImageId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	)

# Download the instance profile from AWS
curl -qsS4f --retry 900 --retry-delay 1 'http://169.254.169.254/latest/dynamic/instance-identity/document' -o /root/instance-profile

# Figure out what region is around us
if [ -z "$AWS_DEFAULT_REGION" ]; then
	AWS_DEFAULT_REGION=$(sed -n '/"region"[[:space:]]*:/s,^.*"region"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' /root/instance-profile)

	# Sanity check
	if [ -z "$AWS_DEFAULT_REGION" -o -n "${AWS_DEFAULT_REGION//[[:alnum:]-]}" ]; then
		echo 'ERROR: cannot determine the AWS region this instance is running in!' >&2
		exit 1
	fi
fi

# Extract the instance id (we could query the meta-data at AWS but we
# already have this information in the profile, so why should we utilise
# the network?
INSTANCE_ID=$(sed -n '/"instanceId"[[:space:]]*:/s,^.*"instanceId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' /root/instance-profile)

# Sanity check
if [ -z "$INSTANCE_ID" -o -n "${INSTANCE_ID//[[:alnum:]-]}" ]; then
	echo 'ERROR: cannot determine the id of this instance!' >&2
	exit 1
fi

SUBNET_ID=$(aws ec2 describe-instances --output json \
			--instance-ids "$INSTANCE_ID" \
		| sed -n '/"SubnetId"[[:space:]]*:/s,^.*"SubnetId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$SUBNET_ID" -o -n "${SUBNET_ID//[[:alnum:]-]}" ]; then
	echo 'ERROR: cannot determine the subnet id of this instance!' >&2
	exit 1
fi

if [ -n "${PRESERVE_STACK:-}" -a -n "${PRESERVE_STACK/[Tt][Rr][Uu][Ee]}" ]; then
	# We may need the VPC id if we are a part of a nested stack structure
	VPC_ID=$(aws ec2 describe-instances --output json \
				--instance-ids "$INSTANCE_ID" \
			| sed -n '/"VpcId"[[:space:]]*:/s,^.*"VpcId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	)

	# Sanity check (if VPC is empty it would mean that we are not inside a VPC)
	if [ -n "${VPC_ID//[[:alnum:]-]}" ]; then
		echo 'ERROR: cannot determine the VPC id of this instance!' >&2
		exit 1
	fi

	# Let's check the sanity of the cfnParentStackId variable since we
	# are going to rely on it at the very end of the process.  The check here
	# is very basic, yet it should protect us from the majority of issues.
	if [ -n "${cfnParentStackId##arn:aws:cloudformation:*:stack/*/*}" ]; then
		echo 'ERROR: the provided parent stack ID does not look to be a valid ID!' >&2
		exit 1
	fi
fi

# If we did not find an image that has the same checksum,
# dive in and generate it
if [ -z "$AMI_ID" -o "${AMI_ID:0:4}" != 'ami-' ]; then

DEVICE_ID=
[ -n "$FS_UUID" ] && DEVICE_ID="UUID=\"$FS_UUID\"" ||:
cat > "$BOOTSTRAP_MNT"/etc/fstab << __EOF__
${DEVICE_ID:-/dev/xvda1}	/		ext4		noatime,nodev			0 1
devtmpfs	/dev		devtmpfs	nosuid,noexec,size=16k,nr_inodes=1000	0 0
tmpfs		/dev/shm	tmpfs		nosuid,noexec,nodev		0 0
devpts		/dev/pts	devpts		nosuid,noexec,gid=5,mode=620	0 0
sysfs		/sys		sysfs		nosuid,noexec,nodev		0 0
proc		/proc		proc		nosuid,noexec,nodev		0 0
tmpfs		/tmp		tmpfs		nosuid,noexec,nodev		0 0
/tmp		/var/tmp	none		bind				0 0
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/fstab
unset DEVICE_ID
unset FS_UUID

install -d -m0755 -o root -g root "$BOOTSTRAP_MNT"/etc/systemd/network
cat > "$BOOTSTRAP_MNT"/etc/systemd/network/zzz-default.network << "__EOF__"
[Network]
DHCP=yes
LLMNR=no

[DHCP]
UseMTU=true
UseDomains=true
UseHostname=false
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/network/zzz-default.network

# configure systemd-resolved (once CentOS 7 gets an updated systemd we
# need to use stub-resolv.conf instead here)
ln -sf /run/systemd/resolve/resolv.conf "$BOOTSTRAP_MNT"/etc/resolv.conf
# are you ready for some sed magic? :) This inserts 'resolve' after
# 'files' in the 'hosts:' line if 'resolve' was not there.
sed -i '/^[[:space:]]*hosts:/{
	H
	s/^[[:space:]]*hosts:[[:space:]]*//
	s/resolve\([[:space:]]*\[!UNAVAIL=return\]\)*//g
	/files/s/files/files resolve [!UNAVAIL=return] /
	/files/!s/^/resolve [!UNAVAIL=return] /
	s/[[:space:]]\+/ /g
	x
	s/^\([[:space:]]*hosts:[[:space:]]*\).*/\1/
	G
	s/\n//g
}' "$BOOTSTRAP_MNT"/etc/nsswitch.conf

# grub configuration
cat > "$BOOTSTRAP_MNT"/etc/default/grub << "__EOF__"
GRUB_CMDLINE_LINUX="crashkernel=auto console=tty0 console=ttyS0 modprobe.blacklist=i2c_piix4 nousb audit=1 quiet"
GRUB_HIDDEN_TIMEOUT=0
__EOF__
chmod 0600 "$BOOTSTRAP_MNT"/etc/default/grub

cat << __EOF__ > "$BOOTSTRAP_MNT"/etc/modprobe.d/blacklist.conf
# The following list of blacklisted modules ensures that irrelevant to AWS EC2
# instances subsystems are not loaded.  The install directives ensure that
# even if a module is implicitly called by something else the actual loading
# procedure will not be triggered.  Some modules are explicitly probed from
# udev, so for these modules the install directive returns successful exit
# code, otherwise log files will contain warnings.
#
__EOF__
chmod 0600 "$BOOTSTRAP_MNT"/etc/modprobe.d/blacklist.conf

for module in \
	ata_generic:false \
	ata_piix:false \
	binfmt_misc:false \
	cirrus:true \
	drm:true \
	drm_kms_helper:true \
	floppy:false \
	i2c_core:true \
	i2c_piix4:false \
	libata:false \
	parport:false \
	parport_pc:false \
	pata_acpi:false \
	pcspkr:false \
	serio_raw:false \
	snd:true \
	snd_pcm:true \
	snd_pcsp:true \
	snd_timer:true \
	soundcore:true \
	ttm:true \
	usbcore:false \
	usbserial:false \
; do
	cat <<-__EOF__ >> "$BOOTSTRAP_MNT"/etc/modprobe.d/blacklist.conf
		blacklist ${module%%:*}
		install ${module%%:*} /bin/${module#*:}
__EOF__
done

for mnt in /dev /proc /sys ; do
	mount "$mnt" "$BOOTSTRAP_MNT$mnt" --rbind --make-rprivate
done
> "$BOOTSTRAP_MNT"/etc/machine-id
chmod 0644 "$BOOTSTRAP_MNT"/etc/machine-id
chroot "$BOOTSTRAP_MNT" grub2-install "$TARGET_VOL"
chroot "$BOOTSTRAP_MNT" grub2-mkconfig -o /boot/grub2/grub.cfg
rm -f "$BOOTSTRAP_MNT"/boot/initramfs-*.img
chroot "$BOOTSTRAP_MNT" /bin/sh -ec '\
	export LANG=C LC_ALL=C ;
	INITRAMFS=$(rpm -ql kernel | grep ^/boot/initramfs- | sort -nr | head -1); \
	KVERS=$(printf "$INITRAMFS" | sed -n "s,^/boot/initramfs-\(.*\)\.img,\1,;T;p"); \
	[ -n "$INITRAMFS" -a -n "$KVERS" ] && \
	dracut --strip --prelink --hardlink --ro-mnt --stdlog 3 --no-hostonly --drivers "xen-blkfront nvme ext4 mbcache jbd2" --force --verbose --show-modules --printsize "$INITRAMFS" "$KVERS" \
'
chroot "$BOOTSTRAP_MNT" /bin/bash -excu -c "
	systemctl mask proc-sys-fs-binfmt_misc.{auto,}mount --no-reload
	systemctl add-wants systemd-resolved nss-lookup.target --no-reload
	mkdir -m755 /etc/systemd/system/systemd-resolved.before
	ln -s /usr/lib/systemd/system/network-online.target /etc/systemd/system/systemd-resolved.before/
	ln -s /usr/lib/systemd/system/nss-lookup.target /etc/systemd/system/systemd-resolved.before/
"

# Setup a custom root user
mkdir -m0 "$BOOTSTRAP_MNT"/root/.users
chroot "$BOOTSTRAP_MNT" useradd -om -u 0 -g 0 -s /bin/bash -d /root/.users/admin r_admin

# Ensure that only SELinux confined user are allowed to login via SSH
printf '%%user_u\n' >> "$BOOTSTRAP_MNT"/etc/security/sepermit.conf

# Be a bit more stricter re: the permissions we do not know about
printf 'handle-unknown=deny\n' >> "$BOOTSTRAP_MNT"/etc/selinux/semanage.conf

# Configure SELinux policy
chroot "$BOOTSTRAP_MNT" /bin/sh -ec "\
	export LANG=C LC_ALL=C ;
	semanage fcontext -N -a -e /tmp-inst /tmp/.private ;
	semanage fcontext -N -a -e /var/tmp-inst /var/tmp/.private ;
	semanage fcontext -N -a -f a -t ssh_home_t '/root/.users/[^/].+/\.ssh(/.*)?' ;

	semanage boolean -N --modify --on  polyinstantiation_enabled ;
	semanage boolean -N --modify --on  deny_execmem ;
	semanage boolean -N --modify --off selinuxuser_execmod ;
	semanage boolean -N --modify --off selinuxuser_execstack ;

	semanage login -a -s root -r 's0-s0:c0.c1023' %root -N ;
	semanage login -m -s user_u -r s0 __default__ -N ;
	semanage login -a -s user_u -r s0 root -N
"

# Ensure that we have sane i18n environment unless explicitly changed
cat > "$BOOTSTRAP_MNT"/etc/locale.conf << "__EOF__"
LANG=C
LC_MESSAGES=C
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/locale.conf

# CentOS 7 is still transitioning from initscripts to systemd.  Therefore,
# if we get rid of the initscripts package we lose the autorelabeling
# functionality.  This means that we have to create our own facility.
cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/systemd/system/autorelabel.service
[Unit]
Description=Relabel all filesystems, if necessary
DefaultDependencies=no
Requires=local-fs.target
Conflicts=shutdown.target
After=local-fs.target
Before=sysinit.target shutdown.target
ConditionSecurity=selinux
ConditionKernelCommandLine=|autorelabel
ConditionPathExists=|/.autorelabel

[Service]
ExecStart=/usr/local/sbin/autorelabel
Type=oneshot
TimeoutSec=0
RemainAfterExit=yes
StandardInput=tty

[Install]
WantedBy=sysinit.target
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/autorelabel.service
chown -h root:root "$BOOTSTRAP_MNT"/etc/systemd/system/autorelabel.service

cat << "__EOF__" > "$BOOTSTRAP_MNT"/usr/local/sbin/autorelabel
#!/bin/bash
#
# Do automatic relabelling
#

relabel_selinux() {
    # if /sbin/init is not labeled correctly this process is running in the
    # wrong context, so a reboot will be required after relabel
    AUTORELABEL=
    . /etc/selinux/config
    echo 0 > /sys/fs/selinux/enforce

    if [ "$AUTORELABEL" = 0 ]; then
	echo
	echo $"*** Warning -- SELinux ${SELINUXTYPE} policy relabel is required. "
	echo $"*** /etc/selinux/config indicates you want to manually fix labeling"
	echo $"*** problems. Dropping you to a shell; the system will reboot"
	echo $"*** when you leave the shell."
	sulogin

    else
	echo
	echo $"*** Warning -- SELinux ${SELINUXTYPE} policy relabel is required."
	echo $"*** Relabeling could take a very long time, depending on file"
	echo $"*** system size and speed of hard drives."

	FORCE=$(</.autorelabel)
        [ -x "/usr/sbin/quotaoff" ] && /usr/sbin/quotaoff -aug
	/sbin/fixfiles $FORCE restore > /dev/null 2>&1
    fi
    rm -f  /.autorelabel
    /usr/lib/dracut/dracut-initramfs-restore
    sync
    systemctl --force reboot
}

restorecon $(awk '!/^#/ && $4 !~ /noauto/ && $2 ~ /^\// { print $2 }' /etc/fstab) >/dev/null 2>&1
relabel_selinux
__EOF__
chmod 0700 "$BOOTSTRAP_MNT"/usr/local/sbin/autorelabel
chown -h root:root "$BOOTSTRAP_MNT"/usr/local/sbin/autorelabel
chroot "$BOOTSTRAP_MNT" systemctl enable autorelabel.service

# A nice touch for a initscript-less system :)
cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/rc.d/init.d/functions
# If you are looking inside this file, most likely you need to install
# the initscripts package, e.g. "yum -y install initscripts"
initscripts_required_error ()
{
	echo "Please install the initscripts package if this functionality is required!" >&2
	exit 1
}

systemctl_redirect() { initscripts_required_error; }
daemon() { initscripts_required_error; }
success() { return; }
failure() { return; }
passed() { return; }
warning() { return; }
action () { "$@"; }
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/rc.d/init.d/functions
chown -h root:root "$BOOTSTRAP_MNT"/etc/rc.d/init.d/functions

# cleanup service (this is to be launched on the initial bootstrap of the instance)
cat > "$BOOTSTRAP_MNT"/root/cleanup.sh << "__EOF__"
#!/bin/bash
set -uxe -o pipefail

# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=1406439
chcon -vh -t bin_t /sbin

mkdir /var/log/journal
chown -h root:systemd-journal /var/log/journal
chmod 02755 /var/log/journal

# clean-up hook for those who want to inject stuff
if [ -s /root/cleanup-addon.sh ]; then
	. /root/cleanup-addon.sh
fi

rm -f /etc/{group,passwd}- /etc/{g,}shadow-
rm -f /etc/nsswitch.conf.bak
rm -f /etc/ssh/ssh_host_*_key*
rm -rf /root/.ssh
rm -rf /var/cache/yum/*

for f in btmp dmesg lastlog tallylog wtmp yum.log ; do [ -s "/var/log/$f" ] && >"/var/log/$f" ; done
rm -rf /var/log/journal/*

>/etc/machine-id

# delete ourselves
systemctl disable template-cleanup.service
rm /etc/systemd/system/template-cleanup.service
rm -f /root/cleanup.sh /root/cleanup-addon.sh

# set the default target to multi-user
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target

# remove our cleanup target
rm /etc/systemd/system/template-cleanup.target

# Power off the instance, so imaging could take place
poweroff --no-wtmp --no-wall
__EOF__
chmod 0700 "$BOOTSTRAP_MNT"/root/cleanup.sh

cat > "$BOOTSTRAP_MNT"/etc/systemd/system/template-cleanup.target << "__EOF__"
[Unit]
Description=Clean Template
Documentation=https://none
Requires=basic.target template-cleanup.service
After=basic.target rescue.service rescue.target
Conflicts=rescue.service rescue.target multi-user.target
AllowIsolate=yes
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/template-cleanup.target
ln -sf template-cleanup.target "$BOOTSTRAP_MNT"/etc/systemd/system/default.target

cat > "$BOOTSTRAP_MNT"/etc/systemd/system/template-cleanup.service << "__EOF__"
[Unit]
Description=Cleaning the template up
Documentation=https://none
Before=poweroff.target

[Service]
ExecStart=/root/cleanup.sh
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/template-cleanup.service

cat > "$BOOTSTRAP_MNT"/etc/systemd/system/authorize-ssh-key.service << "__EOF__"
[Unit]
Description=EC2 SSH Key Installer
Documentation=https://none
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
UMask=077
ExecStart=/usr/bin/curl -qsS4f --retry 900 --retry-delay 1 --create-dirs http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key -o /root/.users/admin/.ssh/authorized_keys
ExecStartPost=/bin/systemctl disable authorize-ssh-key

[Install]
WantedBy=multi-user.target
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/authorize-ssh-key.service
ln -s /etc/systemd/system/authorize-ssh-key.service "$BOOTSTRAP_MNT"/etc/systemd/system/multi-user.target.wants/

cat > "$BOOTSTRAP_MNT"/usr/local/sbin/ec2-user-data-extract-vars.sh << "__EOF__"
#!/bin/sh

set -u

EC2_USERDATA_URL='http://169.254.169.254/latest/user-data'
EC2_USERDATA_ENV=/run/ec2-user-data.env

trap 'rc=$?; trap - EXIT; rm -f -- "$TMPFILE"; exit $rc' EXIT HUP INT QUIT ABRT SEGV TERM
if ! TMPFILE=$(mktemp "$EC2_USERDATA_ENV.XXXXXXXXXX"); then
	printf "ERROR: Failed to create a temporary file in /run/ ($?)\n" >&2
	exit 1
fi

# The following will extract variables from the EC2 user-data.  It also does some
# sanitisation of the lines (i.e. extract lines which look like a variable, where
# name of the variable is alpha-numeric and can contain '_' and where the value is
# allowed to have alpha-numeric and space characters intermixed with selected set
# of punctuation characters (no '$', '`', or '>' are allowed)
set -o pipefail
if ! OUTPUT=$( { curl -qsS4f --retry 120 --retry-delay 1 "$EC2_USERDATA_URL" | \
	sed -n '/^[[:space:]]*[[:alnum:]_]\+=[][[:alnum:][:space:]~!@#%^&*()_=+{}\|:;"'\'',<.\/\?-]\+$/p' | \
	sed 's,^[[:space:]]*,,;s,[[:space:]]*$,,' \
> "$TMPFILE"; } 2>&1 ; RC=$? ; printf "\n$RC\n"; exit $RC ); then
	RC=$(printf '%s' "$OUTPUT" | sed -n '$p')
	if [ -n "${RC//[[:digit:]]}" ]; then
		printf "ERROR: Unexpected exit code received in the subprocess ($RC)!" >&2
		exit 2
	fi

	# unfortunately, curl does not distinguish between HTTP errors, we are
	# interested in HTTP 404 only and should fail if it was anything else
	if [ $RC -eq 22 -a "$OUTPUT" == "${OUTPUT//error: 404 Not Found}" ]; then
		printf "ERROR: Failed to acquire the user-data from the AWS environment ($RC)!\n" >&2
		exit 3
	fi

	# At this point we know that we have gotten HTTP 404
	exit 0
fi

chmod 0644 "$TMPFILE"
[ -x /usr/sbin/restorecon ] && /usr/sbin/restorecon "$TMPFILE" || :
mv -f -- "$TMPFILE" "$EC2_USERDATA_ENV"
trap - EXIT
__EOF__
chmod 0700 "$BOOTSTRAP_MNT"/usr/local/sbin/ec2-user-data-extract-vars.sh

cat > "$BOOTSTRAP_MNT"/etc/systemd/system/ec2-user-data.service << "__EOF__"
[Unit]
Description=EC2 user-data retriever
Documentation=https://none
Wants=network-online.target
After=network-online.target
ConditionVirtualization=vm

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ec2-user-data-extract-vars.sh

[Install]
WantedBy=multi-user.target
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/ec2-user-data.service
ln -s /etc/systemd/system/ec2-user-data.service "$BOOTSTRAP_MNT"/etc/systemd/system/multi-user.target.wants/

cat > "$BOOTSTRAP_MNT"/usr/local/sbin/ec2-bootstrap.sh << "__EOF__"
#!/bin/sh
set -e
[ -z "$SYS_REPO" ] || yum -y install $SYS_REPO
[ -z "$SYS_PKGS" -a -z "$SYS_UPDATE" ] || yum -y update
[ -z "$SYS_PKGS" ] || yum -y install $SYS_PKGS
[ -z "$SYS_SVCS" ] || systemctl start $SYS_SVCS
__EOF__
chmod 0700 "$BOOTSTRAP_MNT"/usr/local/sbin/ec2-bootstrap.sh

cat > "$BOOTSTRAP_MNT"/etc/systemd/system/ec2-bootstrap.service << "__EOF__"
[Unit]
Description=EC2 Bootstrapping script
Documentation=https://none
Requires=ec2-user-data.service
After=ec2-user-data.service
ConditionVirtualization=vm

[Service]
Type=oneshot
EnvironmentFile=-/run/ec2-user-data.env
ExecStart=/usr/local/sbin/ec2-bootstrap.sh
ExecStartPost=/usr/bin/systemctl disable ec2-bootstrap.service

[Install]
WantedBy=multi-user.target
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/systemd/system/ec2-bootstrap.service
ln -s /etc/systemd/system/ec2-bootstrap.service "$BOOTSTRAP_MNT"/etc/systemd/system/multi-user.target.wants/

# Security

printf '\n# Set sane umask for the init process\numask 027' >> "$BOOTSTRAP_MNT"/etc/sysconfig/init

# Deny access via tcp_wrappers except for sshd
printf 'ALL:ALL\n' >> "$BOOTSTRAP_MNT"/etc/hosts.deny
printf 'sshd:ALL\n' >> "$BOOTSTRAP_MNT"/etc/hosts.allow

cat > "$BOOTSTRAP_MNT"/etc/security/namespace.d/tmp.conf << "__EOF__"
/tmp		/tmp/.private/		level:create		root,adm
/var/tmp	/var/tmp/.private/	level:create		root,adm
__EOF__
chmod 0644 "$BOOTSTRAP_MNT"/etc/security/namespace.d/tmp.conf

cat > "$BOOTSTRAP_MNT"/etc/sysctl.d/10-security.conf << "__EOF__"
# We are running a pure x86_64 system and don't need 32-bit support
abi.syscall32 = 0

# Ensure that SUID binaries are not dumpable (default on CentOS 7)
#fs.suid_dumpable = 0

# Openwall-derived protection patches that ensure that the links can be
# created only if the creator has access to the target (default on CentOS 7)
#fs.protected_hardlinks = 1
#fs.protected_symlinks = 1

# Disable custom binaries support (sysctl currently cannot set this)
##fs.binfmt_misc.status = 0

# Disable kernel stack tracer (default on CentOS 7)
#kernel.stack_tracer_enabled = 0

# Employ ASLR (address space layout randomisation) memory techniques
#kernel.randomize_va_space = 2

#
# This toggle indicates whether restrictions are placed on exposing kernel
# addresses via /proc and other interfaces.
# When kptr_restrict is set to (0), the default, there are no restrictions.
# When kptr_restrict is set to (1), kernel pointers printed using the %pK
# format specifier will be replaced with 0's unless the user has CAP_SYSLOG.
# When kptr_restrict is set to (2), kernel pointers printed using %pK will
# be replaced with 0's regardless of privileges.
kernel.kptr_restrict = 1

# disable kexec functionality
kernel.kexec_load_disabled = 1

# disable ftrace (used by kpatch)
kernel.ftrace_enabled = 0

# This toggle indicates whether unprivileged users are prevented from using
# dmesg(8) to view messages from the kernel's log buffer.
# When dmesg_restrict is set to (0), there are no restrictions.
# When dmesg_restrict is set to (1), users must have CAP_SYSLOG to use dmesg(8).
kernel.dmesg_restrict = 1
__EOF__

cat > "$BOOTSTRAP_MNT"/etc/sysctl.d/20-networking.conf << "__EOF__"
# Disable IPv6 networking
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Disable ICMP redirects
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

# Log possibly spoofed packets
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
__EOF__

# Adjust sshd config to be sane
sed -i '
        s#\(^[[:space:]]*PasswordAuthentication[[:space:]]\+\)yes\(.*\|$\)#\1no\2#;
        s#\(^[[:space:]]*PermitEmptyPasswords[[:space:]]\+\)yes\(.*\|$\)#\1no\2#;
        s#\(^[[:space:]]*PermitRootLogin[[:space:]]\+\)\(no\|yes\)\(.*\|$\)#\1without-password\3#;
        s#\(^[[:space:]]*Protocol[[:space:]]\+\)[[:digit:],]\+\(.*\|$\)#\12\2#;
        s#\(^[[:space:]]*StrictModes[[:space:]]\+\)no\(.*\|$\)#\1yes\2#;
        s#\(^[[:space:]]*UsePrivilegeSeparation[[:space:]]\+\)no\(.*\|$\)#\1yes\2#;
        s#\(^[[:space:]]*X11Forwarding[[:space:]]\+\)yes\(.*\|$\)#\1no\2#;
' "$BOOTSTRAP_MNT"/etc/ssh/sshd_config

# Remove all locale and X Window related environment since the only
# locale we have is C and we do not expect running X Window
sed -i '/^\s*#\s\+Accept\s\+locale-related/d;/^\s*AcceptEnv\s\+\(L\|XMODIFIERS\)/d' "$BOOTSTRAP_MNT"/etc/ssh/sshd_config

# Download and install the extensive privileges check tool
curl -qsS4f --retry 900 --retry-delay 1 'https://raw.githubusercontent.com/galaxy4public/check-sugid/master/check-sugid.script' -o "$BOOTSTRAP_MNT"/usr/local/sbin/check-sugid
chmod 0700 "$BOOTSTRAP_MNT"/usr/local/sbin/check-sugid

# Install the default policy for check-sugid
curl -qsS4f --retry 900 --retry-delay 1 'https://raw.githubusercontent.com/galaxy4public/check-sugid/master/policies/centos7' -o "$BOOTSTRAP_MNT"/etc/yum/post-actions/check-sugid.action
chmod 0600 "$BOOTSTRAP_MNT"/etc/yum/post-actions/check-sugid.action

# link check-sugid into yum
curl -qsS4f --retry 900 --retry-delay 1 'https://raw.githubusercontent.com/galaxy4public/yum-plugin-at-exit/master/yum-plugin-at-exit.conf' -o "$BOOTSTRAP_MNT"/etc/yum/pluginconf.d/at-exit.conf
chmod 0644 "$BOOTSTRAP_MNT"/etc/yum/pluginconf.d/at-exit.conf
mkdir -m755 "$BOOTSTRAP_MNT"/etc/yum/pluginconf.d/at-exit.conf.d
ln -s /usr/local/sbin/check-sugid "$BOOTSTRAP_MNT"/etc/yum/pluginconf.d/at-exit.conf.d/

curl -qsS4f --retry 900 --retry-delay 1 'https://raw.githubusercontent.com/galaxy4public/yum-plugin-at-exit/master/yum-plugin-at-exit.helper' -o "$BOOTSTRAP_MNT"/usr/lib/yum-plugins/at-exit.helper
chmod 0755 "$BOOTSTRAP_MNT"/usr/lib/yum-plugins/at-exit.helper

curl -qsS4f --retry 900 --retry-delay 1 'https://raw.githubusercontent.com/galaxy4public/yum-plugin-at-exit/master/yum-plugin-at-exit.py' -o "$BOOTSTRAP_MNT"/usr/lib/yum-plugins/at-exit.py
chmod 0644 "$BOOTSTRAP_MNT"/usr/lib/yum-plugins/at-exit.py

# Apply the check-sugid policies
chroot "$BOOTSTRAP_MNT" /bin/sh -c "grep ':update:' /etc/yum/post-actions/check-sugid.action | grep -vE '^\s*#' | cut -f3- -d':' | sh -x" ||:

cat << "__EOF__" > "$BOOTSTRAP_MNT"/usr/local/sbin/apply-etc-patches.sh
#!/bin/sh -e

PATCH_LIST="$@"
[ -z "$PATCH_LIST" ] && PATCH_LIST='*.diff'

PATCH_CMD='patch -d /etc -p1 --backup-if-mismatch -z .centos -E -F 0 -l -s -t -T'

[ -d /etc/patches ] || exit 0

cd /etc/patches

for patch in $PATCH_LIST ; do
	[ "${patch//\*}" != "$patch" ] && break

	# try to apply the patch in forward direction with --dry-run
	if ! $PATCH_CMD -N --dry-run < "$patch" >/dev/null 2>&1 ; then
		# OK, maybe it's already in place then?
		if ! $PATCH_CMD -R --dry-run < "$patch" >/dev/null 2>&1 ; then
			# ... it seems that the original file is incompatible
			echo "Check failed: '$patch', please investigate!" >&2
		fi
		continue
	fi

	if ! $PATCH_CMD < "$patch" ; then
		echo "Failed to apply: '$patch', please investigate!" >&2
		continue
	fi
done
__EOF__
chmod 0700 "$BOOTSTRAP_MNT"/usr/local/sbin/apply-etc-patches.sh

mkdir -m700 "$BOOTSTRAP_MNT"/etc/patches
cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/patches/bashrc.diff
--- etc/bashrc.centos	2016-11-05 17:19:35.000000000 +0000
+++ etc/bashrc	2017-03-20 02:59:33.608000000 +0000
@@ -68,9 +68,9 @@
     # You could check uidgid reservation validity in
     # /usr/share/doc/setup-*/uidgid file
     if [ $UID -gt 199 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then
-       umask 002
-    else
        umask 022
+    else
+       umask 077
     fi
 
     SHELL=/bin/bash
__EOF__

cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/patches/csh.cshrc.diff
--- etc/csh.cshrc.centos	2016-11-05 17:19:35.000000000 +0000
+++ etc/csh.cshrc	2017-03-20 03:00:28.804000000 +0000
@@ -8,9 +8,9 @@
 # You could check uidgid reservation validity in
 # /usr/share/doc/setup-*/uidgid file
 if ($uid > 199 && "`/usr/bin/id -gn`" == "`/usr/bin/id -un`") then
-    umask 002
-else
     umask 022
+else
+    umask 077
 endif
 
 if ($?prompt) then
__EOF__

cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/patches/profile.diff
--- etc/profile.centos	2016-11-05 17:19:35.000000000 +0000
+++ etc/profile	2017-03-20 03:01:31.243000000 +0000
@@ -57,9 +57,9 @@
 # You could check uidgid reservation validity in
 # /usr/share/doc/setup-*/uidgid file
 if [ $UID -gt 199 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then
-    umask 002
-else
     umask 022
+else
+    umask 077
 fi
 
 for i in /etc/profile.d/*.sh ; do
__EOF__

cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/patches/functions.diff
--- etc/rc.d/init.d/functions.centos	2015-09-16 11:51:07.000000000 +0000
+++ etc/rc.d/init.d/functions	2016-04-03 11:34:40.901000000 +0000
@@ -7,7 +7,7 @@
 TEXTDOMAIN=initscripts

 # Make sure umask is sane
-umask 022
+umask 077

 # Set up a default search path.
 PATH="/sbin:/usr/sbin:/bin:/usr/bin"
__EOF__

chmod 0600 "$BOOTSTRAP_MNT"/etc/patches/*.diff

cat << "__EOF__" > "$BOOTSTRAP_MNT"/etc/yum/post-actions/umask.action
# This yum post-transaction action updates the default umask in /etc
# to be stricter than the default provided by FC/RHEL/CentOS.

# install transaction state is used to cover 'yum reinstall <package>'

setup:install:/usr/local/sbin/apply-etc-patches.sh {bashrc,csh.cshrc,profile}.diff
setup:update:/usr/local/sbin/apply-etc-patches.sh {bashrc,csh.cshrc,profile}.diff
initscripts:install:/usr/local/sbin/apply-etc-patches.sh functions.diff
initscripts:update:/usr/local/sbin/apply-etc-patches.sh functions.diff
__EOF__

chroot "$BOOTSTRAP_MNT" /bin/sh /usr/local/sbin/apply-etc-patches.sh

# SELinux customisations
mkdir -m700 "$BOOTSTRAP_MNT"/root/policies
cat << "__EOF__" > "$BOOTSTRAP_MNT"/root/policies/initd2user.te
# This module allows the init_t to user_t transitions, so one would be able
# to define systemd or SysVinit services that drop user privileges to a
# bare minimum (e.g. drop privileges using DAC followed by confinement in
# the non-privileged SELinux domain.
module initd2user 1.0;

require {
	type init_t;
	attribute unpriv_userdomain;
	class process transition;
}

#============= init_t ==============
allow init_t unpriv_userdomain:process transition;
__EOF__

cat << "__EOF__" > "$BOOTSTRAP_MNT"/root/policies/no_kernel_load_modules.te
module no_kernel_load_modules 1.0;

require {
	type kernel_t;
	attribute daemon;
	class system module_request;
}

dontaudit daemon kernel_t:system module_request;
__EOF__

cat << "__EOF__" > "$BOOTSTRAP_MNT"/root/policies/systemd_resolved.te
# Allow daemons to communicate with resolved over the DBUS interface
module systemd_resolved 1.0;

require {
	type systemd_resolved_t;
	attribute daemon;
	class dbus send_msg;
}

allow daemon systemd_resolved_t:dbus send_msg;
allow systemd_resolved_t daemon:dbus send_msg;
__EOF__

chmod 0600 "$BOOTSTRAP_MNT"/root/policies/*.te

chroot "$BOOTSTRAP_MNT" /bin/sh -exuc '
	cd /root/policies
	for module in *.te ; do
		checkmodule -M -m -o "${module%.te}".{mod,te}
		semodule_package -o "${module%.te}.pp" -m "${module%.te}.mod"
		semodule -N -i "${module%.te}.pp"
		rm "${module%.te}.mod"
	done
'

# Inject custom code into the process if it was provided
for f in /root/bootstrap.d/*.sh ; do
	[ "$f" != '/root/bootstrap.d/*.sh' ] || break
	. "$f"
done

cd /root
umount -R "$BOOTSTRAP_MNT"

# At this point we have a volume with the minimal OS installed, but the
# SELinux labels are wrong and to properly relabel the filesystem we need
# to launch the instance with the proper SELinux policy being active.

# Get the volume id
VOLUME_ID=$(aws ec2 describe-volumes --output=json \
			--filters "Name=attachment.device,Values=/dev/sdf" \
				"Name=attachment.instance-id,Values=$INSTANCE_ID" \
		| sed -n '/"VolumeId"[[:space:]]*:/s,^.*"VolumeId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$VOLUME_ID" -o -n "${VOLUME_ID//[[:alnum:]-]}" ]; then
	echo "ERROR: cannot determine the volume id of '$TARGET_VOL'!" >&2
	exit 1
fi

# XXX: dangerous section -- if we get terminated beyond this we will most
#      likely leave untracked artifacts behind when the stack is removed
#      This must be addressed (probably with registering callbacks in a
#      handler) as part of the upcoming modularisation of this script.

# Snapshot the volume
SNAPSHOT_ID=$(aws ec2 create-snapshot --output json \
			--volume-id "$VOLUME_ID" \
			--description "CentOS 7 minimal bootstrap root volume snapshot" \
		| sed -n '/"SnapshotId"[[:space:]]*:/s,^.*"SnapshotId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$SNAPSHOT_ID" -o -n "${SNAPSHOT_ID//[[:alnum:]-]}" ]; then
	echo "ERROR: cannot determine the snapshot id of the '$TARGET_VOL' volume!" >&2
	exit 1
fi

# Wait until the snapshot is completed
OUTPUT=
I=0
until [ "$OUTPUT" == 'completed' ]; do
	sleep 60
	if [ $I -gt $AWS_TIMEOUT ]; then
		echo "ERROR: the AWS timeout of $AWS_TIMEOUT minutes was exceeded, aborting!" >&2
		break
	fi
	if ! OUTPUT=$(aws ec2 describe-snapshots --output json \
				--snapshot-ids "$SNAPSHOT_ID" \
			| sed -n '/"State"[[:space:]]*:/s,^.*"State"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	); then
		echo 'ERROR: aws ec2 describe-snapshots was abnormally terminated!' >&2
		break
	fi
	if [ "$OUTPUT" != 'pending' -a "$OUTPUT" != 'completed' ]; then
		echo "ERROR: got an unexpected status ($OUTPUT) for the describe-snapshots!" >&2
		break
	fi
	I=$((I + 1))
done

if [ "$OUTPUT" != 'completed' ]; then
	# Delete the snapshot since we do not want to leave it behind
	if ! OUTPUT=$(aws ec2 delete-snapshot --output json \
				--snapshot-id "$SNAPSHOT_ID" \
	); then
		echo 'ERROR: aws ec2 delete-snapshot was abnormally terminated!' >&2
	fi
	exit 1
fi

# Register an image
AMI_ID=$(aws ec2 register-image --output json \
			--name "build-image-$(date +%Y%m%d%H%M%S)" \
			--description 'A temporary image to bootstrap the minimal CentOS 7 instance' \
			--architecture x86_64 --virtualization-type hvm --sriov-net-support simple --ena-support \
			--root-device-name /dev/xvda --block-device-mappings \
				"DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAPSHOT_ID,DeleteOnTermination=true}" \
		| sed -n '/"ImageId"[[:space:]]*:/s,^.*"ImageId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$AMI_ID" -o -n "${AMI_ID//[[:alnum:]-]}" ]; then
	echo 'ERROR: cannot determine the image id of the AMI created from the snapshot!' >&2
	exit 1
fi

# Wait for the image to be available
OUTPUT=
I=0
until [ "$OUTPUT" == 'available' ]; do
	sleep 60
	if [ $I -gt $AWS_TIMEOUT ]; then
		echo "ERROR: the AWS timeout of $AWS_TIMEOUT minutes was exceeded, aborting!" >&2
		exit 1
	fi
	if ! OUTPUT=$(aws ec2 describe-images --output json \
				--image-ids "$AMI_ID" \
			| sed -n '/"State"[[:space:]]*:/s,^.*"State"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	); then
		echo 'ERROR: aws ec2 describe-images was abnormally terminated!' >&2
		exit 1
	fi
	if [ "$OUTPUT" != 'pending' -a "$OUTPUT" != 'available' ]; then
		echo "ERROR: got an unexpected status ($OUTPUT) for the describe-images!" >&2
		exit 1
	fi
	I=$((I + 1))
done

INSTANCE_TYPE=$(sed -n 's,.*"instanceType"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*,\1,;T;p' /root/instance-profile | head -1)
# Launch an instance from the image (we reuse INSTANCE_ID variable here)
INSTANCE_ID=$(aws ec2 run-instances --output json \
			--image-id "$AMI_ID" \
			--no-associate-public-ip-address \
			--instance-type "${INSTANCE_TYPE:-t2.micro}" \
			--instance-initiated-shutdown-behavior stop \
			--subnet-id "$SUBNET_ID" \
		| sed -n '/"InstanceId"[[:space:]]*:/s,^.*"InstanceId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$INSTANCE_ID" -o -n "${INSTANCE_ID//[[:alnum:]-]}" ]; then
	echo 'ERROR: cannot determine the id of the temporary instance!' >&2
	exit 1
fi

# Tag the instance, so the policy would allow its termination
aws ec2 create-tags --resources "$INSTANCE_ID" --tags Key=Name,Value=bootstrap-image/template Key=purpose,Value=build-image

# Wait until the instance is stopped
OUTPUT=
I=0
until [ "$OUTPUT" == 'stopped' ]; do
	sleep 60
	if [ $I -gt $AWS_TIMEOUT ]; then
		echo "ERROR: the AWS timeout of $AWS_TIMEOUT minutes was exceeded, aborting!" >&2
		break
	fi
	if ! OUTPUT=$(aws ec2 describe-instances --output json \
				--instance-ids "$INSTANCE_ID" \
			| sed -n '/"State"[[:space:]]*:[[:space:]]*{/{:again n ; /{/d; /}/d; /"Name"[[:space:]]*:/!b again ; /"Name"[[:space:]]*:/s/^.*"Name"[[:space:]]*:[[:space:]]*"\?\([[:alpha:]]\+\)"\?.*$/\1/;T;p;q ; }' \
	); then
		echo 'ERROR: aws ec2 describe-images was abnormally terminated!' >&2
		break
	fi
	if [ "$OUTPUT" != 'pending' -a "$OUTPUT" != 'running' -a "$OUTPUT" != 'stopping' -a "$OUTPUT" != 'stopped' ]; then
		echo "ERROR: got an unexpected state ($OUTPUT) for the describe-instances!" >&2
		break
	fi
	I=$((I + 1))
done

# At this point we have a stopped instance that contains a clean minimal
# CentOS 7 image. We will get the volume id of the instance and generate
# all the needed images from it.  However, there is some temporary stuff
# laying around: bootstrap snapshot and the image generated from it.
# Now, it is a good time to get rid of all untracked stuff we created
# outside the CloudFormation template.

# remove the temporary AMI
aws ec2 deregister-image --output json --image-id "$AMI_ID"

# remove the temporary snapshot
aws ec2 delete-snapshot --output json --snapshot-id "$SNAPSHOT_ID"

# We postponed the handling of the possible error condition encountered
# in the wait cycle so we do not need to introduce additional cleanup
if [ "$OUTPUT" != 'stopped' ]; then

	# Try to preserve the console output of the temporary instance
	aws ec2 get-console-output --output text \
		--instance-id "$INSTANCE_ID" \
		&> /root/temp-ec2-console.txt ||:

	# Terminate the newly created instance since we do not want to leave it behind
	if ! OUTPUT=$(aws ec2 terminate-instances --output json \
				--instance-ids "$INSTANCE_ID" \
	); then
		echo 'ERROR: aws ec2 terminate-instances was abnormally terminated!' >&2
	fi
	exit 1
fi

# Get the volume id for the created instance
VOLUME_ID=$(aws ec2 describe-volumes --output=json \
			--filters "Name=attachment.device,Values=/dev/xvda" \
				"Name=attachment.instance-id,Values=$INSTANCE_ID" \
		| sed -n '/"VolumeId"[[:space:]]*:/s,^.*"VolumeId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$VOLUME_ID" -o -n "${VOLUME_ID//[[:alnum:]-]}" ]; then
	echo "ERROR: cannot determine the volume id of the root device on the newly created instance!" >&2
	exit 1
fi

# Racing to the finish here ;)

# Snapshot the volume
SNAPSHOT_ID=$(aws ec2 create-snapshot --output json \
			--volume-id "$VOLUME_ID" \
			--description "CentOS 7 minimal root volume (build-image)" \
		| sed -n '/"SnapshotId"[[:space:]]*:/s,^.*"SnapshotId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$SNAPSHOT_ID" -o -n "${SNAPSHOT_ID//[[:alnum:]-]}" ]; then
	echo "ERROR: cannot determine the snapshot id of the '$VOLUME_ID' volume!" >&2
	exit 1
fi

# Wait until the snapshot is completed
OUTPUT=
I=0
until [ "$OUTPUT" == 'completed' ]; do
	sleep 60
	if [ $I -gt $AWS_TIMEOUT ]; then
		echo "ERROR: the AWS timeout of $AWS_TIMEOUT minutes was exceeded, aborting!" >&2
		exit 1
	fi
	if ! OUTPUT=$(aws ec2 describe-snapshots --output json \
				--snapshot-ids "$SNAPSHOT_ID" \
			| sed -n '/"State"[[:space:]]*:/s,^.*"State"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	); then
		echo 'ERROR: aws ec2 describe-snapshots was abnormally terminated!' >&2
		exit 1
	fi
	if [ "$OUTPUT" != 'pending' -a "$OUTPUT" != 'completed' ]; then
		echo "ERROR: got an unexpected status ($OUTPUT) for the describe-snapshots!" >&2
		exit 1
	fi
	I=$((I + 1))
done

# Register an image
AMI_ID=$(aws ec2 register-image --output json \
			--name "build-image-$(date +%Y%m%d%H%M%S)" \
			--description 'A minimal CentOS 7 image' \
			--architecture x86_64 --virtualization-type hvm --sriov-net-support simple --ena-support \
			--root-device-name /dev/xvda --block-device-mappings \
				"DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAPSHOT_ID,DeleteOnTermination=true}" \
		| sed -n '/"ImageId"[[:space:]]*:/s,^.*"ImageId"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
)

# Sanity check
if [ -z "$AMI_ID" -o -n "${AMI_ID//[[:alnum:]-]}" ]; then
	echo 'ERROR: cannot determine the image id of the final AMI created from the snapshot!' >&2
	exit 1
fi

# Be nice to people who are looking at the resources
aws ec2 create-tags --resources "$SNAPSHOT_ID" --tags "Key=Name,Value=AMI: $AMI_ID"
aws ec2 create-tags --resources "$AMI_ID" --tags \
	${AMI_NAME_TAG:+"Key=Name,Value=$AMI_NAME_TAG"} \
	"Key=image/distro,Value=CentOS" \
	"Key=image/distro/release,Value=$DISTRO_RELEASE" \
	"Key=image/checksum,Value=$IMAGE_CHECKSUM" \
	"Key=image/checksum/script,Value=$SCRIPT_CHECKSUM" \
	"Key=created-by,Value=$cfnStackId"

# Wait for the image to be available
OUTPUT=
I=0
until [ "$OUTPUT" == 'available' ]; do
	sleep 60
	if [ $I -gt $AWS_TIMEOUT ]; then
		echo "ERROR: the AWS timeout of $AWS_TIMEOUT minutes was exceeded, aborting!" >&2
		exit 1
	fi
	if ! OUTPUT=$(aws ec2 describe-images --output json \
				--image-ids "$AMI_ID" \
			| sed -n '/"State"[[:space:]]*:/s,^.*"State"[[:space:]]*:[[:space:]]*"\([[:alnum:]-]\+\)".*$,\1,;T;p;q' \
	); then
		echo 'ERROR: aws ec2 describe-images was abnormally terminated!' >&2
		exit 1
	fi
	if [ "$OUTPUT" != 'pending' -a "$OUTPUT" != 'available' ]; then
		echo "ERROR: got an unexpected status ($OUTPUT) for the describe-images!" >&2
		exit 1
	fi
	I=$((I + 1))
done

# Terminate the newly created instance
if ! OUTPUT=$(aws ec2 terminate-instances --output json \
			--instance-ids "$INSTANCE_ID" \
); then
	echo 'ERROR: aws ec2 terminate-instances was abnormally terminated!' >&2
	exit 1
fi

# At this point the only artifacts we have outside the CloudFormation
# template are: an AMI and a snapshot (AMI is tied to the snapshot).

fi # generation of the new image from scratch

# Signal the stack that we created the AMI and provide the AMI ID back
if [ -n "$cfnSignalURL" ]; then
	curl -X PUT -H 'Content-Type:' \
		--data-binary '{"Status" : "SUCCESS","Reason" : "Bootstrap was successful","UniqueId" : "AmiId", "Data" : "'"$AMI_ID"'"}' "$cfnSignalURL"
	trap - ERR HUP INT QUIT TERM KILL ABRT SEGV EXIT
fi

# XXX: another minefield is here.  We reported that the resource was
#      successfully created, but if the parent stack fails for any
#      reason it will trigger the deletion of our stack.  If we are
#      running in a region where Lambda is not available this will
#      result in a deadlock due to the cyclic dependency between the
#      bootstrap image and SQS/SNS for custom resource

get_last_stack_event_stamp()
{
	local stackId="$1"
	local OUTPUT=
	if ! OUTPUT=$(aws cloudformation describe-stack-events --output json \
					--stack-name "$stackId" \
			| sed -n "/\(^\|[[:space:],]\+\)\"Timestamp\"[[:space:]]*:/s,^.*\"Timestamp\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*,\1,;T;p" \
			| sort -nr | head -1 \
	); then
		echo 'ERROR: aws cloudformation describe-stack-events was abnormally terminated!' >&2
		exit 1
	fi
	echo "$OUTPUT"
}

# Wait until the stack is created (we are using the cfnParentStackId
# identifier to optimise logic and not to run the wait cycle twice:
# for a simple stack cfnStackId equals cfnParentStackId)
wait4stack()
{
	local stackId="$1"
	local waitTimeout="${2:-$AWS_TIMEOUT}"
	local stackTimestamp="$(get_last_stack_event_stamp $stackId)"
	local OUTPUT=
	local I=0
	while [ "$OUTPUT" != 'CREATE_COMPLETE' -a "$OUTPUT" != 'UPDATE_COMPLETE' ]; do
		if [ $I -gt $waitTimeout ]; then
			local timeStamp="$(get_last_stack_event_stamp $stackId)"
			if [ "$stackTimestamp" == "$timeStamp" ]; then
				echo "ERROR: there were no stack changes for $waitTimeout minutes, aborting!" >&2
				exit 1
			fi
			stackTimestamp="$timeStamp"
			unset timeStamp
			I=0
		fi
		if ! OUTPUT=$(aws cloudformation describe-stacks --output json \
					--stack-name "$stackId" \
				| sed -n '/"StackStatus"[[:space:]]*:/s,^.*"StackStatus"[[:space:]]*:[[:space:]]*"\([[:upper:]_]\+\)".*$,\1,;T;p;q' \
		); then
			echo 'ERROR: aws cloudformation describe-stacks was abnormally terminated!' >&2
			exit 1
		fi
		case "$OUTPUT" in
			'CREATE_IN_PROGRESS'|'UPDATE_IN_PROGRESS'| \
			'ROLLBACK_IN_PROGRESS'|'UPDATE_ROLLBACK_IN_PROGRESS'| \
			'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS')
				sleep 60
				;;
			'CREATE_COMPLETE'|'UPDATE_COMPLETE')
				break
				;;
			*)
				echo "ERROR: got an unexpected state ($OUTPUT) for the describe-stacks!" >&2
				exit 1
				;;
		esac
		I=$((I + 1))
	done
}

if ! wait4stack "$cfnParentStackId" "$AWS_TIMEOUT"; then
	[ -z "${PRESERVE_STACK:-}" ] && poweroff
fi

if [ -n "${cfnUseQueue-}" ]; then
	# If we are using SQS/SNS to communicate back the AMI ID we no longer
	# need that custom resource.
	aws cloudformation update-stack --stack-name "$cfnStackId" \
		--parameters ParameterKey={BootstrapImage,BootstrapInstanceType,BootstrapVolumeSize,VpcId,SubnetId,PreserveStack,KeyName,BootstrapScriptUrl,ParentStackId,UserData,UpdateTrigger},UsePreviousValue=true \
		--capabilities CAPABILITY_IAM \
		--template-body "$(aws cloudformation get-template --stack-name "$cfnStackId" | jq '.TemplateBody|del(.Resources.AmiQueue)|del(.Outputs.AmiId) + {Outputs: {AmiId: {Description: "The resulting AMI created by the stack", Value: "'$AMI_ID'"}}}')"

	# Here we need to wait for this stack's update before we proceed further.
	wait4stack "$cfnStackId" "$AWS_TIMEOUT"
fi

if [ -z "${PRESERVE_STACK:-}" ]; then
	# OK, now we remove the stack
	aws cloudformation delete-stack --stack-name "$cfnStackId" ||:
elif [ -z "${PRESERVE_STACK/[Tt][Rr][Uu][Ee]}" ]; then
	# The user asked us to preserve the whole stack, so no more work here
	exit 0
else
	# In case we are called from another stack we need to do a manual
	# clean up of the stack resources and preserve the shell of the
	# created stack, otherwise it would be impossible to perform stack
	# updates.

	if [ -z "${VPC_ID:-}" ]; then
		echo "ERROR: The VPC ID is not present but is required for the cleanup process!" >&2
		exit 1
	fi

	# The trick we are using here is to perform a stack update with some
	# placeholder resource still defined in the stack (security groups
	# cost nothing and are the less intrusive resource to keep).
	aws cloudformation update-stack --stack-name "$cfnStackId" --template-body '
{
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "AMI: '"$AMI_ID"'",
	"Parameters": {
		"VpcId": {
			"Type": "String",
			"Default": "'"${VPC_ID:-}"'"
		},
		"SubnetId": {
			"Type": "AWS::EC2::Subnet::Id",
			"Default": "'"${SUBNET_ID:-}"'"
		},
		"ParentStackId": {
			"Type": "String",
			"Default": "'"$cfnParentStackId"'"
		}
	},
	"Resources": {
		"PlaceHolder": {
			"Type": "AWS::CloudFormation::WaitConditionHandle",
			"Properties": { }
		}
	},
        "Outputs": {
		"AmiId": {
			"Value": "'"$AMI_ID"'",
			"Description": "The resulting AMI created by the stack"
		}
	}
}'
fi
