/*
Copyright (C) 2012	Massimo Maggi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
#ifdef __KERNEL__
#include <linux/rculist.h>
#else
#include <net/if.h>
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
#endif
//NETLINK PROTOCOL NUMER
#define NETLINK_CHOOSEIF 30
/* Data about an interface */
struct chooseif_interface_data
{
    char ifname[IFNAMSIZ];            //Interface name
    char inputcounter[IFNAMSIZ];      //rateest counter name for input bandwidth
    char outputcounter[IFNAMSIZ];     //rateest counter name for output bandwith
    __u32 max_input_kbps;	      //Maximum input bandwidth for this interface in kbit/s
    __u32 max_output_kbps;            //Maximum output bandwidth for this interface in kbit/s
    __u32 cost;                       //Parameter used to select a preferred interface (lower cost, most used interface)
    u32 fwmark;                       //NETFILTER MARK to be applied to all packets belonging to connections to be routed through this interface
};

#ifdef __KERNEL__
//This is the struct composing the in-kernel list of interfaces
struct chooseif_interface_entry
{
    struct list_head list;
    struct rcu_head rcu;
    struct xt_rateest *incounter;
    struct xt_rateest *outcounter;
    struct chooseif_interface_data data;
    bool invalidated;
};
#endif
//Data in each netlink packet.
struct chooseif_netlink_msg
{
    int operation;
    struct chooseif_interface_data data;
};
//Possible operations
enum chooseif_netlink_ops
{
    CHIF_NL_OPS_ADD = 2,                 //Add a new interface. Fill the entire data structure.
    CHIF_NL_OPS_DELETE = 3,             //Remove an interface. Fill at least ifname and fwmark in data structure.
    CHIF_NL_OPS_REQLIST = 4,            //Ask kernel to return list of interfaces. Data structure in this packet can be null,
    CHIF_NL_OPS_ELEMLIST = 5,           //Message from kernel to userspace, containing data about one interface.
    CHIF_NL_OPS_ACK = 6,                //Acknowledge. Operation completed successfully-
    CHIF_NL_OPS_NAK = 7			//Not acknowledge. Operation can't be completed successfully. See dmesg.
};
