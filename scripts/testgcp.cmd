export i=1
docmd() { echo "#--------------------------------------"; echo "# $i: $(date)"; echo "#--------------------------------------"; echo "$@"; eval "$@"; i=$(( $i + 1 )); }
echo "Start: $(date)"
docmd uname -a
docmd cat /etc/hostname
docmd curl ip.me
docmd gcloud auth list
docmd gcloud storage buckets list
echo "End: $(date)"
