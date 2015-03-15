#!/bin/sh
#
# Create the ca dir tree.
#
# Author: Xiami(i@f2light.com)
#
echo "This program will initialize an empty CA database under currect directory."
echo "CAUTION: currect CA database will be destroyed."
echo
echo "Please enter CONFIRM to confirm."
echo -n "> "
read confirm

if [ "x$confirm" != "xCONFIRM" ]; then
    echo "Aborted."
    exit
fi

mkdir db
cp /dev/null db/index.txt
echo "01" > db/serial
echo "01" > db/crlnumber
mkdir cert
mkdir privkey
chmod 700 privkey

echo "Finished."
