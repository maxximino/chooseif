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
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>

#include <linux/netfilter/x_tables.h>

static void chooseif_init (struct xt_entry_target *t)
{
/*There is no data to initalize*/
}

static int chooseif_parse (int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
    return 1;
}

static void chooseif_save (const void *ip, const struct xt_entry_target *target)
{
/*There is no data to save*/
}

static struct xtables_target chooseif_target = {
    .family = NFPROTO_UNSPEC,
    .name = "CHOOSEIF",
    .version = XTABLES_VERSION,
    .size = 0,
    .userspacesize = 0,
    .init = chooseif_init,
    .parse = chooseif_parse,
    .save = chooseif_save
};

void _init (void)
{
    xtables_register_target (&chooseif_target);
}
