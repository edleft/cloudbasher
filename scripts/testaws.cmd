export i=1
docmd() { echo "#--------------------------------------"; echo "# $i: $(date)"; echo "#--------------------------------------"; echo "$@"; eval "$@"; i=$(( $i + 1 )); }
echo "Start: $(date)"
docmd uname -a
docmd cat /etc/hostname
docmd curl ip.me
docmd aws sts get-caller-identity
# docmd aws s3 ls
echo "End: $(date)"
