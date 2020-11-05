#!/bin/sh
devices="scull"
for i in `seq 0 3`
do
	touch ${devices}$i
done
rm -rf ${devices}[0-3]

