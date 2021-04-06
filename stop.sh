#!/bin/bash
if [ ! -f stop.sh ]; then
    echo 'stop.sh must be run within its container folder' 1>&2
    exit 1
fi

if [ ! -f pid ]; then
    echo 'ERROR: ./pid file not exist! server already exit?' 1>&2
    exit 1
fi

thepid=`cat ./pid`
kill -s SIGUSR1 $thepid
echo "Now saving, please wait most 60 seconds!" 1>&2

for(( i=1; i < 60; i++ ))
do
	if [ ! -d /proc/$thepid ]; then
		echo "Server exit OK!" 1>&2
		rm -rf pid
		exit 0
	fi
	
	echo $i 1>&2
	sleep 1
done

echo "Try force exit the Server..."
kill -s SIGKILL $thepid
sleep 2

if [ ! -d /proc/$thepid ]; then
	echo "Server exit OK!" 1>&2
	rm -rf pid
	exit 0
fi

echo "Can't exit the Server"
