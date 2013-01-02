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
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/random.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/gen_stats.h>
#include <net/netfilter/xt_rateest.h>
#include <linux/netlink.h>
#include "xt_CHOOSEIF.h"
#define TRUE 1
#define FALSE 0
static struct sock *nl_sock;
static LIST_HEAD (lst_interfaces);
static spinlock_t lst_write_lock;
static int weight_cost = 5;
module_param (weight_cost, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(weight_cost, "Weight of the cost parameter");
static int weight_load = 1;
module_param (weight_load, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(weight_load, "Weight of the calculated load");
static int weight_loadcost = 10;
module_param (weight_loadcost, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(weight_loadcost, "Weight of the sqrt(load*cost)");
static int newton_iterations = 3;
module_param (newton_iterations, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(newton_iterations, "How many iterations of newton metod to calculate sqrt");
static int cur_maxcost = 1;  //Actual maximum interface cost. Used to calculate relative costs.
/**
 * Returns the approximated sqrt.
 * 
 * It is approximated with 2^(log(value)/2) using bit arithmetics and then newton_iterations of newton method.
 * 
 * @param value Input value
 * @return sqrt(value)
 */
static inline __u32 approx_sqrt (__u32 value)
{
    int iter = 0;
    signed long approx = 1 << (get_bitmask_order (value)/2);
    signed long startval = value;
    __u32 val=0;
    for (; iter < newton_iterations; iter++) {
        approx = approx - (((approx * approx) - startval) / ((approx << 1)));
    }
    val=approx;
    return val;
}
/**
 * Walks the list and updates cur_maxcost variable
 */
static void update_maxcost (void)
{
    struct chooseif_interface_entry *ent;
    __u32 new = 1;

    rcu_read_lock ();
    list_for_each_entry_rcu (ent, &lst_interfaces, list) {
        if (unlikely (ent->data.cost > new)) {
            new = ent->data.cost;
        }
    }
    rcu_read_unlock ();
    cur_maxcost = new;
}
/**
 * xtables target - core code of this module
 * @param skb The packet.
 * @param par Parameters from xtables. Currently unused.
 * @return packet destiny. Always XT_CONTINUE.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static unsigned int chooseif_tg (struct sk_buff *skb, const struct xt_target_param *par)
#else
static unsigned int chooseif_tg (struct sk_buff *skb, const struct xt_action_param *par)
#endif
{
    struct chooseif_interface_entry *ent;
    __u32 load, load_in, load_out, weight, best_weight, cur_mark;
    struct nf_conn *ct;
    struct net_device *netdev;
    enum ip_conntrack_info ctinfo;
    char rnd;
    //set actual best weight to the maximum possible value.
    best_weight = 1 << 31;
    cur_mark = 0;
    //Get connection related to this packet
    ct = nf_ct_get (skb, &ctinfo);
    if (unlikely (ct == NULL)) { //Not connection tracked?
        return XT_CONTINUE;  //Do not bother with it.
    }
    if (likely (ctinfo == IP_CT_ESTABLISHED || ctinfo == IP_CT_ESTABLISHED + IP_CT_IS_REPLY) || ctinfo == IP_CT_NEW+IP_CT_IS_REPLY) { //Is it a reply or part of an already estalished connection?
	//So the output interface is already set.
        skb->mark = ct->mark;   //simply copy mark from connection tracking table to the packet
        return XT_CONTINUE;
    } else if (unlikely (ctinfo == IP_CT_RELATED || ctinfo == IP_CT_RELATED + IP_CT_IS_REPLY)) { //Is it a connection related to another?
	//So it must exit through the same interface.
        if (ct->master != NULL) {
            skb->mark = ct->master->mark; //copy the mark from the master connection to the packet
            ct->mark = ct->master->mark; // and to the new connection entry.
            nf_conntrack_event_cache (IPCT_MARK, ct);  //notify netfilter of the change in connection tracking table.
        }
        return XT_CONTINUE;
    } else if (ctinfo == IP_CT_NEW) {  //Is it a new connection?
        rcu_read_lock ();
        list_for_each_entry_rcu (ent, &lst_interfaces, list) {  //Iterate through all available interfaces
		if(ent->invalidated==TRUE){continue;}
            spin_lock_bh (&ent->incounter->lock);
            load_in = ent->incounter->rstats.bps / ent->data.max_input_kbps;   //read load %0 relative to traffic in input 
            spin_unlock_bh (&ent->incounter->lock);	
            spin_lock_bh (&ent->outcounter->lock);
            load_out = ent->outcounter->rstats.bps / ent->data.max_output_kbps; //read load %0 relative to traffic in output
            spin_unlock_bh (&ent->outcounter->lock);
            if (load_out >= load_in) {             //use the highest load %0. If upstream is saturated , do not use the interface even if downstream is almost free. And reverse.
                load = load_out;
            } else {
                load = load_in;
            }
            weight =
                weight_loadcost * approx_sqrt (load * ent->data.cost) + weight_load * load +
                weight_cost * ent->data.cost;  //Calculate actual interface weight
            if (unlikely (weight == best_weight)) {   // Tie!
                get_random_bytes (&rnd, sizeof (rnd));  
                if (rnd % 2 == 1) { //This interface or the previous best?
                    weight++;   //Prefer previous best interface.
                } else {
                    weight--;   //Prefer this.
                }
            }
            if (unlikely (weight < best_weight)) {  //This interface is to be preferred to the other. 
		netdev=dev_get_by_name_rcu(&init_net,((char*)ent->data.ifname)); //Get pointer to the interface struct.
		if(netdev==NULL){
		  ent->invalidated=TRUE;
		  printk("Interface doesn't exist anymore:%s\n",ent->data.ifname);
		continue;
		}else if(likely(netif_running(netdev))){  //Check that it is really running and nobody stumbled upon the cable or yanked the USB connector.
                  cur_mark = ent->data.fwmark;       //Set this packet's future mark to mark related to this interface.
                  best_weight = weight;              //Remember "how preferred is" this interface, actually.
		}
		else{
		  printk("Interfaccia down: %s",ent->data.ifname);  //Complain to dmesg if interface is not running.
		}
            }
        }
        rcu_read_unlock ();
        skb->mark = cur_mark;   //Set the mark of the "best" interface to the packet
        ct->mark = cur_mark;   //and in connection tracking table.
        nf_conntrack_event_cache (IPCT_MARK, ct);  //Notify netfilter about change in connection tracking table.
        return XT_CONTINUE;

    }
    return XT_CONTINUE;
}
/**
 * This function checks if the target can be used in this table and hook
 * @param par Struct with target position informations
 * @return -EINVAL or 0
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static bool chooseif_tg_check (const struct xt_tgchk_param *par)
{
 bool novalue = false;
 bool yesvalue = true;
#else
static int chooseif_tg_check (const struct xt_tgchk_param *par)
{
  int novalue=-EINVAL;
  int yesvalue=0;
#endif

    /*Target should be added only in mangle table*/
    if(strcmp("mangle",par->table)!=0){
	printk(KERN_ERR "Table is %s but should be mangle\n",par->table);
	return novalue;
    }
    /*Target should be added only in PREROUTING or OUTPUT hooks*/
    if (!(par->hook_mask & (1 << NF_INET_PRE_ROUTING)) && !(par->hook_mask & (1 << NF_INET_LOCAL_OUT))){
	printk(KERN_ERR "Hook is %u but should be PREROUTING or OUTPUT\n",par->hook_mask);
	return novalue;
    }
    return yesvalue;
}
/**
 * Send a message over netlink to configuration program in userspace
 * @param buf Message to be sent
 * @param pid Recipient
 */
void netlink_send (struct chooseif_netlink_msg *buf, pid_t pid)
{
    struct nlmsghdr *nlh = NULL;
    struct sk_buff *reply = NULL;
    reply = alloc_skb (NLMSG_SPACE (sizeof (struct chooseif_netlink_msg)), GFP_KERNEL);  //Allocate packet buffer 
    nlh = (struct nlmsghdr *) reply->data;		//Get pointer to netlink header in the packet
    nlh->nlmsg_len = NLMSG_SPACE (sizeof (struct chooseif_netlink_msg));  //Set packet length
    nlh->nlmsg_pid = 0;  //From kernel.
    nlh->nlmsg_flags = 0;
    memcpy (NLMSG_DATA (nlh), buf, sizeof (struct chooseif_netlink_msg));  //Copy data into the buffer.
    skb_put (reply, NLMSG_SPACE (sizeof (struct chooseif_netlink_msg)));   //set skb->tail and len to the right value
    NETLINK_CB (reply).pid = 0;
    NETLINK_CB (reply).dst_group = 0;
    netlink_unicast (nl_sock, reply, pid, MSG_DONTWAIT);  //send the message
}
/**
 * Send an ACK or a NAK
 * @param pid recipient
 * @param success ACK or NAK?
 */
static void acknowledge (pid_t pid, int success)
{
    struct chooseif_netlink_msg ack;
    if (success == TRUE) {
        ack.operation = CHIF_NL_OPS_ACK;
    } else {
        ack.operation = CHIF_NL_OPS_NAK;
    }
    netlink_send (&ack, pid);
}

/**
 * This function sets to zero all unused characters into the buffer
 * 
 * This function is needed because xt_rateest_lookup hashing function uses ALL characters in the buffer, even *after* the first \0 character.
 * 
 * @param ptr Pointer to string buffer
 * @param len Length of the buffer
 */
static inline void zeroafter (char *ptr, int len)
{
    int idx = 0, overwrite = FALSE;

    for (idx = 0; idx < len; idx++) { //Iterate over the entire buffer
        if (overwrite) { //Already met the first \0?
            ptr[idx] = 0;  //This character is a \0.
        } else {
            if (ptr[idx] == 0) { //Is this a \0 ?
                overwrite = TRUE; //Other characters from this point up to the end of the buffer are to be overwritten.
            }
        }
    }
}
/**
 * Purge invalidated entries from the list.
 */
static void purge_list(void)
{
    struct chooseif_interface_entry *ent;
    spin_lock (&lst_write_lock); //Obtain write lock
    list_for_each_entry (ent, &lst_interfaces, list) {   //Enumerate entries
        if (ent->invalidated==TRUE) {
	  //This entry is the soon-to-be-deleted one.
            list_del_rcu (&(ent->list)); //Remove entry, respecting RCU semantics.
            update_maxcost ();
            spin_unlock (&lst_write_lock); //Release write lock
            synchronize_rcu (); //Wait that anyone that held the RCU lock before me, releases it
            xt_rateest_put (ent->incounter); //Release references to rateest counters
            xt_rateest_put (ent->outcounter);
            kfree (ent);
            return;
        }
    }
    spin_unlock (&lst_write_lock); //Release write lock
}
/**
 * Add an interface to the list of available ones.
 * 
 * @param msg Netlink message containing interface data
 * @param pid Pid of process to be notified about outcome of the action.
 */
static void addinterface (struct chooseif_netlink_msg *msg, pid_t pid)
{
    struct chooseif_interface_entry *ent;
    struct chooseif_interface_entry *iter;
    purge_list();
    printk (KERN_INFO "Adding interface %s with mark %u.\n", msg->data.ifname, msg->data.fwmark);
    ent = kzalloc (sizeof (struct chooseif_interface_entry), GFP_KERNEL); //Allocate memory for the new entry.
    if (!ent) {
        acknowledge (pid, FALSE);
        printk (KERN_ERR "Cannot allocate memory in addinterface.\n");
        return;
    }
    memcpy (&ent->data, &msg->data, sizeof (struct chooseif_interface_data)); //Copy interface data from netlink packet to the entry.
    zeroafter ((char *) ent->data.inputcounter, IFNAMSIZ); //Work around xt_rateest_lookup hashing function.
    ent->incounter = xt_rateest_lookup ((char *) ent->data.inputcounter); //Get pointer to this interface input traffic counter.
    if (ent->incounter == NULL) {
        acknowledge (pid, FALSE);
        printk (KERN_ERR "Cannot find rateest counter:%s.\n", ent->data.inputcounter);
        return;
    }
    zeroafter ((char *) ent->data.outputcounter, IFNAMSIZ); //Work around xt_rateest_lookup hashing function.
    ent->outcounter = xt_rateest_lookup ((char *) ent->data.outputcounter); //Get pointer to this interface output traffic counter.
    if (ent->outcounter == NULL) {
        xt_rateest_put (ent->incounter);  //release handle to previously found input counter
	acknowledge (pid, FALSE);
        printk (KERN_ERR "Cannot find rateest counter:%s.\n", ent->data.outputcounter);
        return;
    }
    INIT_LIST_HEAD (&(ent->list));  //Initialize list entry
    spin_lock (&lst_write_lock);   //Get write lock
    rcu_read_lock ();		//rcu read lock
    // Check about duplicates.
    list_for_each_entry_rcu (iter, &lst_interfaces, list) { //For each interface.
        // Interface name and fwmark value MUST be unique.
        if ((strcmp (iter->data.ifname, ent->data.ifname) == 0) || (ent->data.fwmark == iter->data.fwmark)) {
	  //There is another entry with same interface name or with same fwmark. Fail.
            rcu_read_unlock ();
            spin_unlock (&lst_write_lock);
	    xt_rateest_put (ent->incounter);
	    xt_rateest_put (ent->outcounter);
	    //Released all locks held.
            acknowledge (pid, FALSE); //Tell userspace process about the failure.
            printk (KERN_ERR "Tried to add same interface two times.\n");
            return;
        }
    }
    rcu_read_unlock ();
    list_add_rcu (&(ent->list), &lst_interfaces);  //Add the entry to the list.
    update_maxcost ();
    spin_unlock (&lst_write_lock); //Release write lock
    acknowledge (pid, TRUE); //Tell the userspace process that everything is OK.
}
/**
 * An userspace process wants to know about all interfaces used by this module.
 * @param pid Recipient of the list of interfaces
 */
static void listinterfaces (pid_t pid)
{
    struct chooseif_interface_entry *ent;
    struct chooseif_netlink_msg *msg;
    purge_list();
    msg = kzalloc (sizeof (struct chooseif_netlink_msg), GFP_KERNEL); //Allocate space for the message
    if (!msg) {
        acknowledge (pid, FALSE);
        printk (KERN_ERR "Cannot allocate memory in listinterfaces.\n");
        return;
    }
    rcu_read_lock (); //Obtain RCU lock
    list_for_each_entry_rcu (ent, &lst_interfaces, list) {  //For each interface
        msg->operation = CHIF_NL_OPS_ELEMLIST;          //This netlink message is an interface entry
        memcpy (&msg->data, &ent->data, sizeof (struct chooseif_interface_data)); //Copy the entry data
        netlink_send (msg, pid); //Send the message
    }
    rcu_read_unlock (); //Unlock RCU
    kfree(msg);
    acknowledge (pid, TRUE); //Tell the userspace process that the enumeration  is terminated.
}
/**
 * Remove an interface from the list of available ones.
 * 
 * @param msg Netlink message containing interface data, at least name and fwmark
 * @param pid Pid of process to be notified about outcome of the action.
 */
static void delinterface (struct chooseif_netlink_msg *msg, pid_t pid)
{
    struct chooseif_interface_entry *ent;
    purge_list();
    printk (KERN_INFO "Removing interface %s , fwmark %u.\n", msg->data.ifname, msg->data.fwmark);
    spin_lock (&lst_write_lock); //Obtain write lock
    list_for_each_entry (ent, &lst_interfaces, list) {   //Enumerate entries
        if ((strcmp (ent->data.ifname, msg->data.ifname) == 0) && (msg->data.fwmark == ent->data.fwmark)) {
	  //This entry is the soon-to-be-deleted one.
            list_del_rcu (&(ent->list)); //Remove entry, respecting RCU semantics.
            update_maxcost ();
            spin_unlock (&lst_write_lock); //Release write lock
            synchronize_rcu (); //Wait that anyone that held the RCU lock before me, releases it
            xt_rateest_put (ent->incounter); //Release references to rateest counters
            xt_rateest_put (ent->outcounter);
            kfree (ent);
            acknowledge (pid, TRUE); //Tell userspace process that the entry was removed successfully
            return;
        }
    }
    spin_unlock (&lst_write_lock); //Release write lock
    printk (KERN_INFO "Interface %s , fwmark %u NOT FOUND.\n", msg->data.ifname, msg->data.fwmark);
    acknowledge (pid, FALSE); //Tell userspace process about the failure.
}

/**
 * Execute the action asked in the netlink packet
 * @param skb Packet received.
 */
static void netlink_recv (struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    struct chooseif_netlink_msg *msg;
    pid_t pid = 0;
    nlh = (struct nlmsghdr *) skb->data; 
    pid = nlh->nlmsg_pid;
    if(!capable(CAP_NET_ADMIN)){
      acknowledge (pid, FALSE);
      return;
    }
    msg=NLMSG_DATA (nlh);
    switch (msg->operation) { //What am I asked to do?
    case CHIF_NL_OPS_ADD:
        addinterface (msg, pid);
        break;
    case CHIF_NL_OPS_DELETE:
        delinterface (msg, pid);
        break;
    case CHIF_NL_OPS_REQLIST:
        listinterfaces (pid);
        break;
    }

}
/**
 * Struct describing this xtables target
 */
static struct xt_target chooseif_tg_reg __read_mostly = {
    .name = "CHOOSEIF",
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .checkentry = chooseif_tg_check,
    .target = chooseif_tg,
    .targetsize = 0,
    .me = THIS_MODULE,
};

static int __init module_load (void)
{
    nl_sock = netlink_kernel_create (&init_net, NETLINK_CHOOSEIF, 0, netlink_recv, NULL, THIS_MODULE); //Create the netlink socket
    spin_lock_init (&lst_write_lock);
    if (!nl_sock) {
        printk (KERN_ERR "Cannot create Netlink socket!\n");
        return -1; //Module can't be configurated, so don't allow it to be inserted.
    }
    return xt_register_target (&chooseif_tg_reg); //If xtables target can be registered, everything is OK, otherwise the module can'be used.
}

static void __exit module_unload (void)
{
    struct chooseif_interface_entry *ent;
    struct chooseif_interface_entry *tmp;
    xt_unregister_target (&chooseif_tg_reg);  //Unregister this target
    netlink_kernel_release (nl_sock); //Release the netlink socket
    synchronize_rcu (); //target is unregistered, netlink is closed, from now on, it's impossible to start new "operations". Wait for pending ones..
    //spin_lock (&lst_write_lock);
    list_for_each_entry_safe (ent,tmp, &lst_interfaces, list) { //Remove every entry in the list
        list_del (&(ent->list)); //Remove it
        xt_rateest_put (ent->incounter); 
        xt_rateest_put (ent->outcounter); //Release rateest counter handles
        kfree (ent); //Free the entry
    }
    //spin_unlock (&lst_write_lock);
}


module_init (module_load);
module_exit (module_unload);

MODULE_AUTHOR ("Massimo Maggi");
MODULE_AUTHOR ("Giovanni Matteo Fumarola");
MODULE_DESCRIPTION ("Progetto PSR");
MODULE_LICENSE ("GPL");
