#!/bin/sh
uci set mysqld.@mysqld[0].enabled='1'
uci commit mysqld
/etc/init.d/mysqld start
/etc/init.d/mysqld status
/etc/init.d/mysqld enable
