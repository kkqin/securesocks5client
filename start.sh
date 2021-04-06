ulimit -s 2048
ulimit -n 102400
ulimit -c unlimited

if [ ! -f start.sh ]; then
    echo 'start.sh must be run within its container folder' 1>&2
    exit 1
fi

if [ ! -f gamesvr ]; then
    echo "ERROR: gamesvr file not exist!" 1>&2
    exit 1
fi

thepid=`cat ./pid 2>/dev/null`
if [ -f pid -a -d /proc/$thepid ]; then
    echo "Server already started!" 1>&2
    exit 0
fi
rm -rf pid

chmod 0755 ./*.sh
chmod 0755 ./gamesvr

`pwd`/gamesvr -d 2>> notice.log &

