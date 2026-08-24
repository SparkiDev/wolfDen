/**
 * @file Det.h
 * Minimal AUTOSAR Default Error Tracer stand-in, for testing the Mka
 * module's development-error reporting without a generated Det.
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
 * Declares the one Det entry point the Mka module calls, so a build with
 * MKA_DEV_ERROR_DETECT == STD_ON links without a generated Det. In a real
 * integration the platform's own Det.h is found on the include path instead.
 */

#ifndef MKA_TEST_DET_H
#define MKA_TEST_DET_H

/* Lets a build with MKA_DEV_ERROR_DETECT == STD_ON compile and run without a
 * generated Det module. The signature is the AUTOSAR one, so the test exercises
 * the binding's real default wiring - Mka.h's own
 * Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, sid, err) - rather than an
 * override that bypasses it. test_autosar.c implements this and records the
 * reports so they can be asserted.
 *
 * Not part of the library: it lives in test/ and is never installed. */

#include "wolfmka/autosar/Mka_Std.h"

Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId,
    uint8 ErrorId);

#endif /* MKA_TEST_DET_H */
