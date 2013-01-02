#!/bin/bash

function add(){
  ifname="$1"
  input="$2"
  output="$3"
  cost="$4"
  mark="$5"
  input_counter=${ifname}_i
  output_counter=${ifname}_o
  #create input data counter
  iptables -t mangle -A PREROUTING -i $ifname -j RATEEST --rateest-name $input_counter --rateest-interval 250ms --rateest-ewmalog 4s
  #create output data counter
  iptables -t mangle -A POSTROUTING -o $ifname -j RATEEST --rateest-name $output_counter --rateest-interval 250ms --rateest-ewmalog 4s
  #add the interface to the kernel table of available interfaces.
  chooseif_lowlevel -a $ifname  $input_counter $output_counter $input $output $cost $mark  
  if [ $? -ne 0 ]; then
     echo "Cannot add interface $ifname to the kernel table. See kernel log."
       iptables -t mangle -D PREROUTING $(echo $(iptables -t mangle -L PREROUTING -n  |egrep -n "^RATEEST.*name $input_counter.*$" |sed s/:/\\t/ |cut -f1) -2 |bc);
       iptables -t mangle -D POSTROUTING $(echo $(iptables -t mangle -L POSTROUTING -n |egrep -n "^RATEEST.*name $output_counter.*$" |sed s/:/\\t/ |cut -f1) -2 |bc);
     exit
  fi
}

function delete(){
  ifname="$1"
  RIGA=$(chooseif_lowlevel -l raw |grep ^$ifname)  #Check that the interface is in the list.
  if [ $? -eq 0 ]; then
    mark=$(echo "$RIGA" |cut -f7)
    chooseif_lowlevel -d $ifname $mark
    if [ $? -ne 0 ];then
      echo "Cannot remove interface $ifname. See kernel log."
      exit
    else
      input_counter=$(echo "$RIGA" |cut -f2)
      output_counter=$(echo "$RIGA" |cut -f3)
      iptables -t mangle -D PREROUTING $(echo $(iptables -t mangle -L PREROUTING -n  |egrep -n "^RATEEST.*name $input_counter.*$" |sed s/:/\\t/ |cut -f1) -2 |bc);
      iptables -t mangle -D POSTROUTING $(echo $(iptables -t mangle -L POSTROUTING -n |egrep -n "^RATEEST.*name $output_counter.*$" |sed s/:/\\t/ |cut -f1) -2 |bc);
    fi  
  else 
    echo "The interface isn't in kernel table"
    exit
  fi
}

#Check if I have CAP_NET_ADMIN throuch /proc/self/status

if [ $(( $(echo 'ibase=16;' $(cat /proc/self/status  |grep CapEff |cut -f2 |tr a-f A-F) |bc) & 4096 )) -ne 4096 ]; then 
  echo You do not have CAP_NET_ADMIN capability. Are you root?
  exit
fi

#Check if the module kernel is loaded
modprobe xt_CHOOSEIF

#Check if needed iptables rules are present, and add them if necessary.
#table mangle - chain PREROUTING
iptables -t mangle -L PREROUTING -n |grep CHOOSEIF >/dev/null 
if [ $? -ne 0 ]; then
  iptables -t mangle -A PREROUTING -j CHOOSEIF
fi
#table mangle - chian OUTPUT
iptables -t mangle -L OUTPUT -n |grep CHOOSEIF >/dev/null 
if [ $? -ne 0 ]; then
  iptables -t mangle -A OUTPUT -j CHOOSEIF
fi
#Masquerade all connections!
iptables -t nat -L POSTROUTING -n |grep MASQUERADE >/dev/null 
if [ $? -ne 0 ]; then
  iptables -t nat -A POSTROUTING -j MASQUERADE
fi

mode="$1"
	
if [ -z $mode ]; then
  mode="-h"
fi
case $mode in
  #Operation in case of request list of interface connected.
  -l)  
      echo -e "Interface Name\tMax input rate (kbps)\tMax output rate (kbps)\tCost\tGateway"
      chooseif_lowlevel -l raw | while read RIGA; do
	echo -en "$(echo "$RIGA"|cut -f 1)\t\t"
	echo -en "$(echo "$RIGA"|cut -f 4)\t\t\t"
	echo -en "$(echo "$RIGA"|cut -f 5)\t\t\t"
	echo -en "$(echo "$RIGA"|cut -f 6)\t"
	mark=$(echo "$RIGA"|cut -f 7)
	echo $(ip route show table $mark |grep default\ via |cut -d' ' -f3)
      done
      if [ $? -ne 0 ];then
	echo "Cannot get the list."
	exit
      fi
  ;;
#Operation in case of delete
  -d)  
     ifname="$2" 
     if [ ! -n $ifname ]; then    
        echo "A needed parameter wasn't specified. See $0 -h "
        exit
     else
       RIGA=$(chooseif_lowlevel -l raw |grep ^$ifname)
       mark=$(echo "$RIGA" |cut -f7)
       delete $ifname $mark  #Delete the interface from the kernel table
       ip route del default table $mark   #remove the route from the routing table
       ip rule del fwmark $mark table $mark   #remove the rule to access that routing table.
     fi
#Operation in case of add
  ;;	
  -a)   
    ifname="$2"
    input="$3"
    output="$4"
    cost="$5"
    gateway="$6"
    if [ -z $gateway ];then
       echo "A needed parameter wasn't specified. See $0 -h "
       exit
    fi
    ip link show $ifname  |grep UP >/dev/null 
    if [ $? -ne 0 ]; then
      echo "The interface is not valid and in state UP";
      exit
    fi
    chooseif_lowlevel -l |grep ^$ifname >/dev/null 
    if [ $? -eq 0 ]; then
       echo "The interface is already connected"
       exit
    fi
    #Calcoulate the fwmark for the new interface
    mark=$(chooseif_lowlevel -l raw |cut -f7 |sort -n |tail -n1)  #get highest existing mark
    if [ -z $mark ]; then
       mark=1000    #starting mark
    else
       mark=$( echo $mark + 1 |bc)    #add one to existing highest
    fi
    ip route add default via $gateway table $mark      #add the route in the routing table
    ip rule add fwmark $mark table $mark               #add the rule to link the fwmark to the specified routing table
    add $ifname $input $output $cost $mark 
    if [ $? -ne 0 ]; then
      echo "Cannot add the interface. See kernel log."
      exit
    fi
  ;;
  #Operation in case of edit		
  -e)
     ifname="$2"
     elementchange="$3"
     newvalue="$4"
     if [ -z $newvalue ]; then    
        echo "A needed parameter wasn't specified. See $0 -h "
        exit
     else
        RIGA=$(chooseif_lowlevel -l raw |grep ^$ifname)
	if [ $? -ne 0 ]; then
	   echo "The interface isn't in kernel table"
	   exit
	else
            mark=$(echo "$RIGA" |cut -f7)
            case "$elementchange" in
            input_rate) 
               input=$newvalue 
               output=$(echo "$RIGA" |cut -f5)       
               cost=$(echo "$RIGA" |cut -f6) 
               delete $ifname $mark
               add $ifname $input $output $cost $mark
            ;;
            output_rate) 
               output=$newvalue
               input=$(echo "$RIGA" |cut -f4)       
               cost=$(echo "$RIGA" |cut -f6) 
               delete $ifname $mark
               add $ifname $input $output $cost $mark
            ;;
            cost) 
               cost=$newvalue
               output=$(echo "$RIGA" |cut -f5)       
               input=$(echo "$RIGA" |cut -f4) 
               delete $ifname $mark
               add $ifname $input $output $cost $mark
            ;;
            gateway) 
              gateway=$newvalue
              ip route change table $mark default via $gateway
              if [ $? -ne 0 ]; then
                 echo "Cannot change routing table."
                 exit
              fi    
            ;;
            *) echo "Invalid parameter. See $0 -h"
            ;;
            esac
       fi
   fi
	  

;;
-h)
	  cat <<EOF
Usage:
Add an interface: $0 -a [interface name] [max input rate] [max output rate] [cost] [gateway]

List interfaces: $0 -l

Remove an interface: $0 -d [interface name]

Edit interface parameter: $0 -e [interface name] [parameter name] [new parameter value]
       Possibile values for parameter name: input_rate, output_rate, cost, gateway.

Data rates are in kbps.
EOF
	  exit
;;
*) 
  echo "Invalid parameter. See $0 -h"
;;
esac

