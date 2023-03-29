/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Tests for implementation of cryptographic protocols.
 *
 * @version $Id$
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

static int sample_ecdsa() {
    printf("hello");
    
	int code = RLC_ERR;
	bn_t d, r, s;  // 大整数
	ec_t q;  // 椭圆曲线的点
	uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
    printf("hello");
	bn_null(d);
	bn_null(r);
	bn_null(s);
	ec_null(q);
    printf("hello");

    bn_new(d);
    bn_new(r);
    bn_new(s);
    ec_new(q);
    printf("hello");

    // 生成公私钥
    cp_ecdsa_gen(d, q);

    // 签名：输入消息
    cp_ecdsa_sig(r, s, m, sizeof(m), 0, d);
    // 验证签名
    cp_ecdsa_ver(r, s, m, sizeof(m), 0, q);

    // 签名：输入哈希值
    cp_ecdsa_sig(r, s, h, RLC_MD_LEN, 1, d);
    // 验证签名
    cp_ecdsa_ver(r, s, h, RLC_MD_LEN, 1, q);

	bn_free(d);
	bn_free(r);
	bn_free(s);
	ec_free(q);
	return code;
}

int main(){
    printf("hello");
    sample_ecdsa();
    return 0;
}