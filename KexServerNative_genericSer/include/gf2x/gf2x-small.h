/* This file is part of the gf2x library.

   Copyright 2007, 2008, 2009, 2010, 2012, 2013, 2015
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

/* Main file for Karatsuba and Toom-Cook multiplication over GF(2)[x]. */

#ifndef GF2X_SMALL_H_
#define GF2X_SMALL_H_

#include "gf2x.h"

/* the header files included here will either put macros in the
 * namespaces GF2X_* or gf2x_*, or possibly macros with generally
 * accepted meaning such as GF2X_MAYBE_UNUSED and such */
#include "gf2x/gf2x-config-export.h"    /* GF2X_HAVE_* macros */
#include "gf2x/gf2x-impl-export.h"      /* utility macros */
#include "gf2x/gf2x-thresholds.h"       /* GF2X_STORAGE_CLASS_* macros */

#ifdef __cplusplus
extern "C" {
#endif

GF2X_STORAGE_CLASS_mul1 void
gf2x_mul1(unsigned long *c, unsigned long a, unsigned long b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul_1_n unsigned long
gf2x_mul_1_n(unsigned long *cp, const unsigned long *bp, long sb, unsigned long a)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_addmul_1_n unsigned long
gf2x_addmul_1_n(unsigned long *dp,
        const unsigned long *cp, const unsigned long* bp,
        long sb, unsigned long a)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul2 void
gf2x_mul2(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul3 void
gf2x_mul3(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul4 void
gf2x_mul4(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul5 void
gf2x_mul5(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul6 void
gf2x_mul6(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul7 void
gf2x_mul7(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul8 void
gf2x_mul8(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;
GF2X_STORAGE_CLASS_mul9 void
gf2x_mul9(unsigned long *c, const unsigned long *a, const unsigned long *b)
        GF2X_MAYBE_UNUSED;

#ifdef __cplusplus
}
#endif

/* This seems rather useless. The point here is that for tuning, we must
 * define the sub-functions of the to-be-tuned implementation differently
 * from the ones of the currently enabled implementation (we use tuning_
 * as a prefix). That implementation might happen to be actually the same
 * code. If we don't do this, we end up with duplicate static functions
 * in the compilation units.
 */
#ifndef GF2X_FUNC
#define GF2X_FUNC(x)       reserved_ ## x
#endif

/* This file provides all the small-sized gf2x_mul1..gf2x_mul9 routines. It is
 * meant to be possibly included directly by applications. */

#include "gf2x/gf2x_mul1.h"
#include "gf2x/gf2x_mul2.h"
#include "gf2x/gf2x_mul3.h"
#include "gf2x/gf2x_mul4.h"
#include "gf2x/gf2x_mul5.h"
#include "gf2x/gf2x_mul6.h"
#include "gf2x/gf2x_mul7.h"
#include "gf2x/gf2x_mul8.h"
#include "gf2x/gf2x_mul9.h"

#ifdef TUNING
#include "tuning_undef_wrapper.h"
#endif

#endif  /* GF2X_SMALL_H_ */
