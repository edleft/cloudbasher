export i=1
docmd() { echo "#--------------------------------------"; echo "# $i: $(date)"; echo "#--------------------------------------"; echo "$@"; eval "$@"; i=$(( $i + 1 )); }
echo "Start: $(date)"
docmd uname -a
docmd hostname
docmd curl ip.me
docmd az account show
docmd az ad signed-in-user show
docmd az storage account list
echo "End: $(date)"
