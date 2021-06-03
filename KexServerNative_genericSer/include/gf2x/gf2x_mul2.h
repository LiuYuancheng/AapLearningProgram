/* This file is part of the gf2x library.

   Copyright 2007, 2008, 2009, 2010, 2013, 2015
   Richard Brent, Pierrick Gaudry, Emmanuel Thome', Paul Zimmermann

   This program is free software; you can redistribute it and/or modify it
   under the terms of either:
    - If the archive contains a file named toom-gpl.c (not a trivial
    placeholder), the GNU General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.
    - If the archive contains a file named toom-gpl.c which is a trivial
    placeholder, the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the license text for more details.
   
   You should have received a copy of the GNU General Public License as
   well as the GNU Lesser General Public License along with this program;
   see the files COPYING and COPYING.LIB.  If not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
   02110-1301, USA.
*/

#ifndef GF2X_MUL2_H_
#define GF2X_MUL2_H_

#include "gf2x.h"
/* All gf2x source files for lowlevel functions must include gf2x-small.h
 * This is mandatory for the tuning mechanism. */
#include "gf2x/gf2x-small.h"

GF2X_STORAGE_CLASS_mul2 void gf2x_mul2(unsigned long *c, const unsigned long *a, const unsigned long *b)
{
   unsigned long t;
   unsigned long u[2];

   gf2x_mul1 (c, a[0], b[0]);
   gf2x_mul1 (c+2, a[1], b[1]);
   t    = c[1]^c[2];
   gf2x_mul1 (u, a[0]^a[1], b[0]^b[1]);
   c[1] = c[0]^u[0]^t;
   c[2] = c[3]^u[1]^t;
}

#endif  /* GF2X_MUL2_H_ */
