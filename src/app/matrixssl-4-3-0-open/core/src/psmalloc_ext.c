/**
 *      @file    psmalloc_ext.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      Additional helper functions for memory allocation.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "coreApi.h"
#include "psUtil.h"

/******************************************************************************/
/*
    Free pointed memory and clear the pointer to avoid accidental
    double free.
 */
void psFreeAndClear(void *ptrptr, psPool_t *pool)
{
    void *ptr;

    if (ptrptr != NULL)
    {
        ptr = *(void **) ptrptr;
        psFree(ptr, pool);
        *(void **) ptrptr = NULL;
        PS_PARAMETER_UNUSED(pool); /* Parameter can be unused. */
    }
}
