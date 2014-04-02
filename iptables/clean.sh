#!/bin/sh
#======================= IPTABLES RULES ========================================
#清除链的规则
$IPT -F
$IPT -t nat -F

#清除封包计数器
$IPT -Z
$IPT -t nat -Z

#设置默认策略
$IPT -P INPUT DROP
$IPT -P FORWAD ACCEPT
$IPT -P OUTPUT DROP



