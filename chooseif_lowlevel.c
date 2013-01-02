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
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include "xt_CHOOSEIF.h"
int netlink_fd = -1;
struct sockaddr_nl netlink_dstaddr;
/**
 * This function allows to send a struct to the kernel module. 
 * The struct to send contains all the information used by kernel module to do a operation.
 *
 * @param *buffer The pointer to the struct to send.
 * @param len The size of the struct to send.
 * @return 0 the operation is successfull, other value in case of failure.
 */
int send_netlink (void *buffer, int len)
{
	struct msghdr msg;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;

	nlh = (struct nlmsghdr *) malloc (NLMSG_SPACE (len));
	memset (nlh, 0, NLMSG_SPACE (len));
	memcpy (NLMSG_DATA (nlh), buffer, len);
	nlh->nlmsg_len = len;
	nlh->nlmsg_pid = getpid ();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 0;
	//  printf ("my pid:%i", nlh->nlmsg_pid);
	iov.iov_base = (void *) nlh;
	iov.iov_len = NLMSG_SPACE (len);
	memset (&msg, 0, sizeof (msg));
	msg.msg_name = (void *) &netlink_dstaddr;
	msg.msg_namelen = sizeof (netlink_dstaddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	return sendmsg (netlink_fd, &msg, 0);
}
/**
 * This function allows to connect the program user-space to kernel module by using netlink.
 *
 * @return The value of the new socket created for this comunication.
 */
int connect_netlink ()
{
	struct sockaddr_nl s_nladdr;

	memset (&s_nladdr, 0, sizeof (s_nladdr));
	s_nladdr.nl_family = AF_NETLINK;
	s_nladdr.nl_pad = 0;
	s_nladdr.nl_pid = getpid ();
	memset (&netlink_dstaddr, 0, sizeof (netlink_dstaddr));
	netlink_dstaddr.nl_family = AF_NETLINK;
	netlink_dstaddr.nl_pad = 0;
	netlink_dstaddr.nl_pid = 0;   /* destined to kernel */

	netlink_fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_CHOOSEIF);
	if (netlink_fd < 0)
	{
		return -1;
	}
	return bind (netlink_fd, (struct sockaddr *) &s_nladdr, sizeof (s_nladdr));
}
/**
 * This function allows to disconnect the program user-space to kernel module.
 */
void disconnect_netlink ()
{
	close (netlink_fd);
}
/**
 * This function allows to receive a struct from the kernel module. 
 *
 * @param *buffer The pointer to the struct to receive.
 * @param len The size of the struct to receive.
 * @return 0 the operation is successfull, other value in case of failure.
 */
int receive_netlink (void *buffer, int len)
{
	struct msghdr msg;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int rv;
	nlh = (struct nlmsghdr *) malloc (NLMSG_SPACE (len));
	memset (nlh, 0, NLMSG_SPACE (len));
	iov.iov_base = (void *) nlh;
	iov.iov_len = NLMSG_SPACE (len);
	memset (&msg, 0, sizeof (msg));
	msg.msg_name = (void *) &netlink_dstaddr;
	msg.msg_namelen = sizeof (netlink_dstaddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	rv = recvmsg (netlink_fd, &msg, 0);
	if (rv > 0)
	{
		memcpy (buffer, NLMSG_DATA (nlh), rv);
	}
	return rv;
}
/**
 * This function allows to print to screen the help.
 */
void help ()
{
	printf ("Usage: ./user [option] [parameters]\n");
        printf ("\n");
        printf ("-h\n");
        printf ("Display this help and exit\n");
        printf ("\n");
        printf ("-l\n");
        printf ("Display the list of interface connected\n");
        printf ("\n");
        printf ("-d [inteface name] [mark]\n");
        printf ("Disconnect an interface\n");
        printf ("\n");
        printf ("-a [interface name] [input counter] [output counter] [max input] [max output] [cost] [mark]\n");
        printf ("Connect an interface\n");
	return;
}
/**
 * @param argv Contains all the information about the parameters.
 */
int main (int argc, char *argv[])
{

	struct chooseif_netlink_msg sndmesg;
	struct chooseif_netlink_msg rcvmesg;
	int result = 1;
	int c = 1;
	int raw=0;
	cap_flag_value_t cap = CAP_CLEAR;
        cap_t caps = cap_get_proc();
        if (caps == NULL)
                return 0;
        cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &cap);
        if(cap == CAP_CLEAR){
	  printf("You don't have CAP_NET_ADMIN (are you root?)\n. Cannot continue.\n");
	  return 1;
	}
        //Check the number of command line arguments
	if (argc == 1)
	{
		help ();
		result = 1;
		return result;
	}
        //Help requested
        else if (strcmp (argv[1], "-h") == 0)
	{
		help ();
		result = 0;
		return result;
	}
        //Add operation
	else if (strcmp (argv[1], "-a") == 0)
	{
		if (argc != 9)
		{
			help ();
			result = 1;
			return result;
		}
                //Copy all parameters from input to the struct to send
		strcpy (sndmesg.data.ifname, argv[2]);
		strcpy (sndmesg.data.inputcounter, argv[3]);
		strcpy (sndmesg.data.outputcounter, argv[4]);
		sndmesg.data.max_input_kbps = atoi (argv[5]);
		sndmesg.data.max_output_kbps = atoi (argv[6]);
		sndmesg.data.cost = atoi (argv[7]);
		sndmesg.data.fwmark = atoi (argv[8]);
		sndmesg.operation = CHIF_NL_OPS_ADD;
	}
        //Delete operation
	else if (strcmp (argv[1], "-d") == 0)
	{
		if (argc != 4)
		{
			help ();
			result = 1;
			return result;
		}
                //Copy all parameters from input to the struct to send
		strcpy (sndmesg.data.ifname, argv[2]);
		sndmesg.data.fwmark = atoi (argv[3]);
		sndmesg.operation = CHIF_NL_OPS_DELETE;
	}
        //List interfaces
	else if (strcmp(argv[1],"-l")==0){
		sndmesg.operation = CHIF_NL_OPS_REQLIST;
	}
	else{
        //Error!
		help ();
		result = 1;
		return result;
	}
        //Open socket to kernel module
	if (connect_netlink () < 0)
	{
		result = 1;
		return result;
	}
        //Send/receive information to/from kernel module in case of adding or deleting
	if ((strcmp (argv[1], "-a") == 0) || (strcmp (argv[1], "-d") == 0))
	{
		send_netlink (&sndmesg, sizeof (struct chooseif_netlink_msg));
		receive_netlink (&rcvmesg, sizeof (struct chooseif_netlink_msg));
		if (rcvmesg.operation == CHIF_NL_OPS_ACK)
		{
			result = 0;
		}
		else
		{
			result = 1;
		}
	}
	else{
        //Send/receive information to/from kernel module in case of request list of interface connected
		if (strcmp (argv[1], "-l") == 0)
		{
                        if(argc >=3 && (strcmp(argv[2],"raw") == 0)){
			 raw=1;
			}
			send_netlink (&sndmesg, sizeof (struct chooseif_netlink_msg));
			rcvmesg.operation = 0;
			if(raw==0) printf("Interface Name\tInput Counter\tOutput Counter\tMax Input\tMax Output\tCost\tMark\n");
			
			do{
				receive_netlink (&rcvmesg, sizeof (struct chooseif_netlink_msg));
				if (rcvmesg.operation == CHIF_NL_OPS_ACK)
				{
					//printf ("ACK received.\n");
					result = 0;
					break;
				}
				else if (rcvmesg.operation == CHIF_NL_OPS_ELEMLIST)
				{
				      result=-1; //wait..
				      //Print to screen all the information of the interface connected
				      if(raw==0){
					printf ("%s\t\t%s\t\t%s\t\t%u\t\t%u\t\t%u\t%u\n", rcvmesg.data.ifname,
							      rcvmesg.data.inputcounter, rcvmesg.data.outputcounter,
							      rcvmesg.data.max_input_kbps,
							      rcvmesg.data.max_output_kbps, rcvmesg.data.cost,
							      rcvmesg.data.fwmark);
				      }
				      else {
					printf ("%s\t%s\t%s\t%u\t%u\t%u\t%u\n", rcvmesg.data.ifname,
							      rcvmesg.data.inputcounter, rcvmesg.data.outputcounter,
							      rcvmesg.data.max_input_kbps,
							      rcvmesg.data.max_output_kbps, rcvmesg.data.cost,
							      rcvmesg.data.fwmark); 
				      }
				}
				else
				{
					result = 1;
                                        break;
				}
			}
			while (result == -1);

		}}

         //Clean up by closing the socket
	disconnect_netlink ();
	return result;
}


