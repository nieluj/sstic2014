and r0, r0, r0	; loc_0 : 0x50 0x00
jmp Z, loc_70	; loc_2 : 0xa0 0x6c
movh r1, 0x0	; loc_4 : 0x21 0x00
movl r1, 0x3	; loc_6 : 0x11 0x03
sub r2, r1, r0	; loc_8 : 0x72 0x10
jmp S, loc_1e	; loc_a : 0xa8 0x12
movh r2, 0x0	; loc_c : 0x22 0x00
movl r2, 0x2	; loc_e : 0x12 0x02
imul r1, r0, r2	; loc_10 : 0x81 0x02
sub r1, r1, r2	; loc_12 : 0x71 0x12
movh r0, 0xf0	; loc_14 : 0x20 0xf0
movl r0, 0x0	; loc_16 : 0x10 0x00
add r0, r0, r1	; loc_18 : 0x60 0x01
call sub_b0	; loc_1a : 0xc0 0x94
ret 0, 0x0	; loc_1c : 0xd0 0x00


loc_1e:
movh r1, 0x0	; loc_1e : 0x21 0x00
movl r1, 0x2b	; loc_20 : 0x11 0x2b
movh r0, 0xfe	; loc_22 : 0x20 0xfe
movl r0, 0x5a	; loc_24 : 0x10 0x5a
call sub_e6	; loc_26 : 0xc0 0xbe

loc_28:
xor r0, r0, r0	; loc_28 : 0x30 0x00
movh r1, 0xfc	; loc_2a : 0x21 0xfc
movl r1, 0x10	; loc_2c : 0x11 0x10
movh r2, 0x0	; loc_2e : 0x22 0x00
movl r2, 0x1	; loc_30 : 0x12 0x01
strb r2, [r1 + r0]	; loc_32 : 0xf2 0x10
jmp loc_28	; loc_34 : 0xb3 0xf2
movh r0, 0xfc	; loc_36 : 0x20 0xfc
movl r0, 0x22	; loc_38 : 0x10 0x22
call sub_b0	; loc_3a : 0xc0 0x74
and r5, r0, r0	; loc_3c : 0x55 0x00
movh r0, 0xfc	; loc_3e : 0x20 0xfc
movl r0, 0x20	; loc_40 : 0x10 0x20
call sub_b0	; loc_42 : 0xc0 0x6c
and r1, r5, r5	; loc_44 : 0x51 0x55
call sub_e6	; loc_46 : 0xc0 0x9e
ret 8, 0x0	; loc_48 : 0xd8 0x00

movh r0, 0xfc	; loc_4a : 0x20 0xfc
movl r0, 0x20	; loc_4c : 0x10 0x20
call sub_b0	; loc_4e : 0xc0 0x60
movh r6, 0xfc	; loc_50 : 0x26 0xfc
movl r6, 0x12	; loc_52 : 0x16 0x12
movh r1, 0x0	; loc_54 : 0x21 0x00
movl r1, 0x1	; loc_56 : 0x11 0x01
xor r4, r4, r4	; loc_58 : 0x34 0x44

loc_5a:
ldrb r5, [r6 + r1]	; loc_5a : 0xe5 0x61
ldrb r2, [r6 + r4]	; loc_5c : 0xe2 0x64
ldrb r3, [r6 + r4]	; loc_5e : 0xe3 0x64
sub r3, r3, r2	; loc_60 : 0x73 0x32
jmp NZ, loc_5a	; loc_62 : 0xa7 0xf6
movh r3, 0x1	; loc_64 : 0x23 0x01
movl r3, 0x0	; loc_66 : 0x13 0x00
imul r2, r2, r3	; loc_68 : 0x82 0x23
or r1, r2, r5	; loc_6a : 0x41 0x25
call sub_c4	; loc_6c : 0xc0 0x56
ret 8, 0x0	; loc_6e : 0xd8 0x00


loc_70:
movh r1, 0x0	; loc_70 : 0x21 0x00
movl r1, 0xe	; loc_72 : 0x11 0x0e
movh r0, 0xfe	; loc_74 : 0x20 0xfe
movl r0, 0x86	; loc_76 : 0x10 0x86
call sub_e6	; loc_78 : 0xc0 0x6c
movh r4, 0x0	; loc_7a : 0x24 0x00
movl r4, 0x2	; loc_7c : 0x14 0x02
movh r1, 0xfd	; loc_7e : 0x21 0xfd
movl r1, 0x28	; loc_80 : 0x11 0x28
movh r0, 0xf0	; loc_82 : 0x20 0xf0
movl r0, 0x0	; loc_84 : 0x10 0x00
call sub_c4	; loc_86 : 0xc0 0x3c
add r0, r0, r4	; loc_88 : 0x60 0x04
movh r1, 0xfd	; loc_8a : 0x21 0xfd
movl r1, 0x36	; loc_8c : 0x11 0x36
call sub_c4	; loc_8e : 0xc0 0x34
add r0, r0, r4	; loc_90 : 0x60 0x04
movh r1, 0xfd	; loc_92 : 0x21 0xfd
movl r1, 0x4a	; loc_94 : 0x11 0x4a
call sub_c4	; loc_96 : 0xc0 0x2c
movh r0, 0xfc	; loc_98 : 0x20 0xfc
movl r0, 0x20	; loc_9a : 0x10 0x20
xor r1, r1, r1	; loc_9c : 0x31 0x11
movh r2, 0x0	; loc_9e : 0x22 0x00
movl r2, 0x36	; loc_a0 : 0x12 0x36
call sub_d6	; loc_a2 : 0xc0 0x32
movh r0, 0xfc	; loc_a4 : 0x20 0xfc
movl r0, 0x3a	; loc_a6 : 0x10 0x3a
movh r1, 0xef	; loc_a8 : 0x21 0xef
movl r1, 0xfe	; loc_aa : 0x11 0xfe
call sub_c4	; loc_ac : 0xc0 0x16
ret 8, 0x0	; loc_ae : 0xd8 0x00


sub_b0:
movh r1, 0x0	; loc_b0 : 0x21 0x00
movl r1, 0x1	; loc_b2 : 0x11 0x01
movh r2, 0x1	; loc_b4 : 0x22 0x01
movl r2, 0x0	; loc_b6 : 0x12 0x00
ldrb r3, [r0 + r1]	; loc_b8 : 0xe3 0x01
sub r1, r1, r1	; loc_ba : 0x71 0x11
ldrb r4, [r0 + r1]	; loc_bc : 0xe4 0x01
imul r4, r4, r2	; loc_be : 0x84 0x42
or r0, r3, r4	; loc_c0 : 0x40 0x34
ret 0, 0xf	; loc_c2 : 0xd0 0x0f


sub_c4:
movh r2, 0x0	; loc_c4 : 0x22 0x00
movl r2, 0x1	; loc_c6 : 0x12 0x01
movh r3, 0x1	; loc_c8 : 0x23 0x01
movl r3, 0x0	; loc_ca : 0x13 0x00
strb r1, [r0 + r2]	; loc_cc : 0xf1 0x02
sub r2, r2, r2	; loc_ce : 0x72 0x22
idiv r1, r1, r3	; loc_d0 : 0x91 0x13
strb r1, [r0 + r2]	; loc_d2 : 0xf1 0x02
ret 0, 0xf	; loc_d4 : 0xd0 0x0f


loc_d6:
movh r3, 0x0	; loc_d6 : 0x23 0x00
movl r3, 0x1	; loc_d8 : 0x13 0x01
and r2, r2, r2	; loc_da : 0x52 0x22
jmp Z, loc_e4	; loc_dc : 0xa0 0x06
sub r2, r2, r3	; loc_de : 0x72 0x23
strb r1, [r0 + r2]	; loc_e0 : 0xf1 0x02
jmp loc_d6	; loc_e2 : 0xb3 0xf2

loc_e4:
ret 0, 0xf	; loc_e4 : 0xd0 0x0f


sub_e6:
and r14, r0, r0	; loc_e6 : 0x5e 0x00
movh r13, 0xfc	; loc_e8 : 0x2d 0xfc
movl r13, 0x0	; loc_ea : 0x1d 0x00
movh r12, 0xf0	; loc_ec : 0x2c 0xf0
movl r12, 0x0	; loc_ee : 0x1c 0x00
xor r8, r8, r8	; loc_f0 : 0x38 0x88
and r9, r8, r8	; loc_f2 : 0x59 0x88
movh r10, 0x0	; loc_f4 : 0x2a 0x00
movl r10, 0x1	; loc_f6 : 0x1a 0x01
xor r11, r11, r11	; loc_f8 : 0x3b 0xbb

loc_fa:
and r1, r1, r1	; loc_fa : 0x51 0x11
jmp Z, loc_118	; loc_fc : 0xa0 0x1a
add r9, r14, r8	; loc_fe : 0x69 0xe8
sub r9, r9, r12	; loc_100 : 0x79 0x9c
jmp S, loc_10c	; loc_102 : 0xa8 0x08
add r9, r14, r8	; loc_104 : 0x69 0xe8
sub r9, r9, r13	; loc_106 : 0x79 0x9d
jmp NS, loc_10c	; loc_108 : 0xac 0x02
jmp loc_11a	; loc_10a : 0xb0 0x0e

loc_10c:
xor r9, r9, r9	; loc_10c : 0x39 0x99
ldrb r9, [r14 + r8]	; loc_10e : 0xe9 0xe8
strb r9, [r13 + r11]	; loc_110 : 0xf9 0xdb
add r8, r8, r10	; loc_112 : 0x68 0x8a
sub r1, r1, r10	; loc_114 : 0x71 0x1a
jmp loc_fa	; loc_116 : 0xb3 0xe2

loc_118:
ret 0, 0xf	; loc_118 : 0xd0 0x0f


loc_11a:
movh r1, 0x0	; loc_11a : 0x21 0x00
movl r1, 0x33	; loc_11c : 0x11 0x33
movh r0, 0xfe	; loc_11e : 0x20 0xfe
movl r0, 0x26	; loc_120 : 0x10 0x26
call sub_e6	; loc_122 : 0xc3 0xc2
jmp loc_28	; loc_124 : 0xb3 0x02
db 0x5b, 0x45	; loc_126
db 0x52, 0x52	; loc_128
db 0x4f, 0x52	; loc_12a
db 0x5d, 0x20	; loc_12c
db 0x50, 0x72	; loc_12e
db 0x69, 0x6e	; loc_130
db 0x74, 0x69	; loc_132
db 0x6e, 0x67	; loc_134
db 0x20, 0x61	; loc_136
db 0x74, 0x20	; loc_138
db 0x75, 0x6e	; loc_13a
db 0x61, 0x6c	; loc_13c
db 0x6c, 0x6f	; loc_13e
db 0x77, 0x65	; loc_140
db 0x64, 0x20	; loc_142
db 0x61, 0x64	; loc_144
db 0x64, 0x72	; loc_146
db 0x65, 0x73	; loc_148
db 0x73, 0x2e	; loc_14a
db 0x20, 0x43	; loc_14c
db 0x50, 0x55	; loc_14e
db 0x20, 0x68	; loc_150
db 0x61, 0x6c	; loc_152
db 0x74, 0x65	; loc_154
db 0x64, 0x2e	; loc_156
db 0xa, 0x0	; loc_158
db 0x5b, 0x45	; loc_15a
db 0x52, 0x52	; loc_15c
db 0x4f, 0x52	; loc_15e
db 0x5d, 0x20	; loc_160
db 0x55, 0x6e	; loc_162
db 0x64, 0x65	; loc_164
db 0x66, 0x69	; loc_166
db 0x6e, 0x65	; loc_168
db 0x64, 0x20	; loc_16a
db 0x73, 0x79	; loc_16c
db 0x73, 0x74	; loc_16e
db 0x65, 0x6d	; loc_170
db 0x20, 0x63	; loc_172
db 0x61, 0x6c	; loc_174
db 0x6c, 0x2e	; loc_176
db 0x20, 0x43	; loc_178
db 0x50, 0x55	; loc_17a
db 0x20, 0x68	; loc_17c
db 0x61, 0x6c	; loc_17e
db 0x74, 0x65	; loc_180
db 0x64, 0x2e	; loc_182
db 0xa, 0x0	; loc_184
db 0x53, 0x79	; loc_186
db 0x73, 0x74	; loc_188
db 0x65, 0x6d	; loc_18a
db 0x20, 0x72	; loc_18c
db 0x65, 0x73	; loc_18e
db 0x65, 0x74	; loc_190
db 0x2e, 0xa	; loc_192
db 0x0, 0x0	; loc_194
db 0x0, 0x0	; loc_196
db 0x0, 0x0	; loc_198
db 0x0, 0x0	; loc_19a
db 0x0, 0x0	; loc_19c
db 0x0, 0x0	; loc_19e
db 0x0, 0x0	; loc_1a0
db 0x0, 0x0	; loc_1a2
db 0x0, 0x0	; loc_1a4
db 0x0, 0x0	; loc_1a6
db 0x0, 0x0	; loc_1a8
db 0x0, 0x0	; loc_1aa
db 0x0, 0x0	; loc_1ac
db 0x0, 0x0	; loc_1ae
db 0x0, 0x0	; loc_1b0
db 0x0, 0x0	; loc_1b2
db 0x0, 0x0	; loc_1b4
db 0x0, 0x0	; loc_1b6
db 0x0, 0x0	; loc_1b8
db 0x0, 0x0	; loc_1ba
db 0x0, 0x0	; loc_1bc
db 0x0, 0x0	; loc_1be
db 0x0, 0x0	; loc_1c0
db 0x0, 0x0	; loc_1c2
db 0x0, 0x0	; loc_1c4
db 0x0, 0x0	; loc_1c6
db 0x0, 0x0	; loc_1c8
db 0x0, 0x0	; loc_1ca
db 0x0, 0x0	; loc_1cc
db 0x0, 0x0	; loc_1ce
db 0x0, 0x0	; loc_1d0
db 0x0, 0x0	; loc_1d2
db 0x0, 0x0	; loc_1d4
db 0x0, 0x0	; loc_1d6
db 0x0, 0x0	; loc_1d8
db 0x0, 0x0	; loc_1da
db 0x0, 0x0	; loc_1dc
db 0x0, 0x0	; loc_1de
db 0x0, 0x0	; loc_1e0
db 0x0, 0x0	; loc_1e2
db 0x0, 0x0	; loc_1e4
db 0x0, 0x0	; loc_1e6
db 0x0, 0x0	; loc_1e8
db 0x0, 0x0	; loc_1ea
db 0x0, 0x0	; loc_1ec
db 0x0, 0x0	; loc_1ee
db 0x0, 0x0	; loc_1f0
db 0x0, 0x0	; loc_1f2
db 0x0, 0x0	; loc_1f4
db 0x0, 0x0	; loc_1f6
db 0x0, 0x0	; loc_1f8
db 0x0, 0x0	; loc_1fa
db 0x0, 0x0	; loc_1fc
db 0x0, 0x0	; loc_1fe
db 0x0, 0x0	; loc_200
db 0x0, 0x0	; loc_202
db 0x0, 0x0	; loc_204
db 0x0, 0x0	; loc_206
db 0x0, 0x0	; loc_208
db 0x0, 0x0	; loc_20a
db 0x0, 0x0	; loc_20c
db 0x0, 0x0	; loc_20e
db 0x0, 0x0	; loc_210
db 0x0, 0x0	; loc_212
db 0x0, 0x0	; loc_214
db 0x0, 0x0	; loc_216
db 0x0, 0x0	; loc_218
db 0x0, 0x0	; loc_21a
db 0x0, 0x0	; loc_21c
db 0x0, 0x0	; loc_21e
db 0x0, 0x0	; loc_220
db 0x0, 0x0	; loc_222
db 0x0, 0x0	; loc_224
db 0x0, 0x0	; loc_226
db 0x0, 0x0	; loc_228
db 0x0, 0x0	; loc_22a
db 0x0, 0x0	; loc_22c
db 0x0, 0x0	; loc_22e
db 0x0, 0x0	; loc_230
db 0x0, 0x0	; loc_232
db 0x0, 0x0	; loc_234
db 0x0, 0x0	; loc_236
db 0x0, 0x0	; loc_238
db 0x0, 0x0	; loc_23a
db 0x0, 0x0	; loc_23c
db 0x0, 0x0	; loc_23e
db 0x0, 0x0	; loc_240
db 0x0, 0x0	; loc_242
db 0x0, 0x0	; loc_244
db 0x0, 0x0	; loc_246
db 0x0, 0x0	; loc_248
db 0x0, 0x0	; loc_24a
db 0x0, 0x0	; loc_24c
db 0x0, 0x0	; loc_24e
db 0x0, 0x0	; loc_250
db 0x0, 0x0	; loc_252
db 0x0, 0x0	; loc_254
db 0x0, 0x0	; loc_256
db 0x0, 0x0	; loc_258
db 0x0, 0x0	; loc_25a
db 0x0, 0x0	; loc_25c
db 0x0, 0x0	; loc_25e
db 0x0, 0x0	; loc_260
db 0x0, 0x0	; loc_262
db 0x0, 0x0	; loc_264
db 0x0, 0x0	; loc_266
db 0x0, 0x0	; loc_268
db 0x0, 0x0	; loc_26a
db 0x0, 0x0	; loc_26c
db 0x0, 0x0	; loc_26e
db 0x0, 0x0	; loc_270
db 0x0, 0x0	; loc_272
db 0x0, 0x0	; loc_274
db 0x0, 0x0	; loc_276
db 0x0, 0x0	; loc_278
db 0x0, 0x0	; loc_27a
db 0x0, 0x0	; loc_27c
db 0x0, 0x0	; loc_27e
db 0x0, 0x0	; loc_280
db 0x0, 0x0	; loc_282
db 0x0, 0x0	; loc_284
db 0x0, 0x0	; loc_286
db 0x0, 0x0	; loc_288
db 0x0, 0x0	; loc_28a
db 0x0, 0x0	; loc_28c
db 0x0, 0x0	; loc_28e
db 0x0, 0x0	; loc_290
db 0x0, 0x0	; loc_292
db 0x0, 0x0	; loc_294
db 0x0, 0x0	; loc_296
db 0x0, 0x0	; loc_298
db 0x0, 0x0	; loc_29a
db 0x0, 0x0	; loc_29c
db 0x0, 0x0	; loc_29e
db 0x0, 0x0	; loc_2a0
db 0x0, 0x0	; loc_2a2
db 0x0, 0x0	; loc_2a4
db 0x0, 0x0	; loc_2a6
db 0x0, 0x0	; loc_2a8
db 0x0, 0x0	; loc_2aa
db 0x0, 0x0	; loc_2ac
db 0x0, 0x0	; loc_2ae
db 0x0, 0x0	; loc_2b0
db 0x0, 0x0	; loc_2b2
db 0x0, 0x0	; loc_2b4
db 0x0, 0x0	; loc_2b6
db 0x0, 0x0	; loc_2b8
db 0x0, 0x0	; loc_2ba
db 0x0, 0x0	; loc_2bc
db 0x0, 0x0	; loc_2be
db 0x0, 0x0	; loc_2c0
db 0x0, 0x0	; loc_2c2
db 0x0, 0x0	; loc_2c4
db 0x0, 0x0	; loc_2c6
db 0x0, 0x0	; loc_2c8
db 0x0, 0x0	; loc_2ca
db 0x0, 0x0	; loc_2cc
db 0x0, 0x0	; loc_2ce
db 0x0, 0x0	; loc_2d0
db 0x0, 0x0	; loc_2d2
db 0x0, 0x0	; loc_2d4
db 0x0, 0x0	; loc_2d6
db 0x0, 0x0	; loc_2d8
db 0x0, 0x0	; loc_2da
db 0x0, 0x0	; loc_2dc
db 0x0, 0x0	; loc_2de
db 0x0, 0x0	; loc_2e0
db 0x0, 0x0	; loc_2e2
db 0x0, 0x0	; loc_2e4
db 0x0, 0x0	; loc_2e6
db 0x0, 0x0	; loc_2e8
db 0x0, 0x0	; loc_2ea
db 0x0, 0x0	; loc_2ec
db 0x0, 0x0	; loc_2ee
db 0x0, 0x0	; loc_2f0
db 0x0, 0x0	; loc_2f2
db 0x0, 0x0	; loc_2f4
db 0x0, 0x0	; loc_2f6
db 0x0, 0x0	; loc_2f8
db 0x0, 0x0	; loc_2fa
db 0x0, 0x0	; loc_2fc
db 0x0, 0xa	; loc_2fe
