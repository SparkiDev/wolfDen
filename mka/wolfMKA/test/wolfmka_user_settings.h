/* wolfmka_user_settings.h (test)
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of wolfMKA.
 *
 * wolfMKA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMKA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Demonstrates the platform configuration hook: compile every source with
 * -DWOLFMKA_USER_SETTINGS -Itest and this header centralises the small-stack
 * switch and a custom allocator. Used by `make test-alloc`.
 */
#ifndef WOLFMKA_USER_SETTINGS_TEST_H
#define WOLFMKA_USER_SETTINGS_TEST_H

#include <stddef.h>

/* Move large locals onto the heap... */
#define WOLFMKA_SMALL_STACK

/* ...and route every allocation through our own counting allocator. */
void* mka_test_malloc(size_t sz, void* heap, int type);
void mka_test_free(void* ptr, void* heap, int type);

#define WOLFMKA_MALLOC(sz, heap, type) mka_test_malloc((sz), (heap), (type))
#define WOLFMKA_FREE(ptr, heap, type)  mka_test_free((ptr), (heap), (type))

#endif
