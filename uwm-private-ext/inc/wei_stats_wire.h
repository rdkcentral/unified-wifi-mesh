/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WEI_STATS_WIRE_H
#define WEI_STATS_WIRE_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

// Generic, struct-agnostic byte-cursor pack/unpack helpers for building
// endianness-safe wire payloads (no struct overlay, no reliance on compiler
// packing behavior), matching the cursor style already used elsewhere to
// build TLVs (see em_vendor.cpp, em_configuration.cpp). Every multi-byte
// integer field is converted to/from network byte order; byte buffers are
// copied verbatim since byte order doesn't apply to byte arrays.

// htonl()/ntohl() are their own inverse, but there's no standard 64-bit
// equivalent; compose one from two 32-bit swaps (endian-neutral on same-endian
// hosts, byte-swaps correctly across differing-endian hosts).
static inline uint64_t wei_hton64(uint64_t v)
{
    return (static_cast<uint64_t>(htonl(static_cast<uint32_t>(v & 0xffffffffULL))) << 32) |
           htonl(static_cast<uint32_t>(v >> 32));
}
static inline uint64_t wei_ntoh64(uint64_t v) { return wei_hton64(v); }

static inline unsigned char *wei_put_bytes(unsigned char *p, const void *src, size_t len)
{
    memcpy(p, src, len);
    return p + len;
}
static inline unsigned char *wei_put_u32(unsigned char *p, uint32_t v)
{
    uint32_t n = htonl(v);
    return wei_put_bytes(p, &n, sizeof(n));
}
static inline unsigned char *wei_put_u64(unsigned char *p, uint64_t v)
{
    uint64_t n = wei_hton64(v);
    return wei_put_bytes(p, &n, sizeof(n));
}
static inline unsigned char *wei_put_u8(unsigned char *p, uint8_t v)
{
    *p = v;
    return p + 1;
}

static inline const unsigned char *wei_get_bytes(const unsigned char *p, void *dst, size_t len)
{
    memcpy(dst, p, len);
    return p + len;
}
static inline const unsigned char *wei_get_u32(const unsigned char *p, uint32_t *v)
{
    uint32_t n;
    p = wei_get_bytes(p, &n, sizeof(n));
    *v = ntohl(n);
    return p;
}
static inline const unsigned char *wei_get_u64(const unsigned char *p, uint64_t *v)
{
    uint64_t n;
    p = wei_get_bytes(p, &n, sizeof(n));
    *v = wei_ntoh64(n);
    return p;
}
static inline const unsigned char *wei_get_u8(const unsigned char *p, uint8_t *v)
{
    *v = *p;
    return p + 1;
}

#endif // WEI_STATS_WIRE_H
