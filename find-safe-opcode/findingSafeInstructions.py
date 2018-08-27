#!/usr/bin/env python

# author: greyshell
# description: finding allowed operations from allowed chars set

# http://www.mlsite.net/8086/8086_table.txt
strmap = """00	ADD		Eb	Gb
01	ADD		Ev	Gv
02	ADD		Gb	Eb
03	ADD		Gv	Ev
04	ADD		AL	Ib
05	ADD		eAX	Iv
06	PUSH	ES
07	POP		ES
08	OR		Eb	Gb
09	OR		Ev	Gv
0A	OR		Gb	Eb
0B	OR		Gv	Ev
0C	OR		AL	Ib
0D	OR		eAX	Iv
0E	PUSH	CS
0F	--
10	ADC		Eb	Gb
11	ADC		Ev	Gv
12	ADC		Gb	Eb
13	ADC		Gv	Ev
14	ADC		AL	Ib
15	ADC		eAX	Iv
16	PUSH	SS
17	POP		SS
18	SBB		Eb	Gb
19	SBB		Ev	Gv
1A	SBB		Gb	Eb
1B	SBB		Gv	Ev
1C	SBB		AL	Ib
1D	SBB		eAX	Iv
1E	PUSH	DS
1F	POP		DS
20	AND		Eb	Gb
21	AND		Ev	Gv
22	AND		Gb	Eb
23	AND		Gv	Ev
24	AND		AL	Ib
25	AND		eAX	Iv
26	ES:
27	DAA
28	SUB		Eb	Gb
29	SUB		Ev	Gv
2A	SUB		Gb	Eb
2B	SUB		Gv	Ev
2C	SUB		AL	Ib
2D	SUB		eAX	Iv
2E	CS:
2F	DAS
30	XOR		Eb	Gb
31	XOR		Ev	Gv
32	XOR		Gb	Eb
33	XOR		Gv	Ev
34	XOR		AL	Ib
35	XOR		eAX	Iv
36	SS:
37	AAA
38	CMP		Eb	Gb
39	CMP		Ev	Gv
3A	CMP		Gb	Eb
3B	CMP		Gv	Ev
3C	CMP		AL	Ib
3D	CMP		eAX	Iv
3E	DS:
3F	AAS
40	INC		eAX
41	INC		eCX
42	INC		eDX
43	INC		eBX
44	INC		eSP
45	INC		eBP
46	INC		eSI
47	INC		eDI
48	DEC		eAX
49	DEC		eCX
4A	DEC		eDX
4B	DEC		eBX
4C	DEC		eSP
4D	DEC		eBP
4E	DEC		eSI
4F	DEC		eDI
50	PUSH	eAX
51	PUSH	eCX
52	PUSH	eDX
53	PUSH	eBX
54	PUSH	eSP
55	PUSH	eBP
56	PUSH	eSI
57	PUSH	eDI
58	POP		eAX
59	POP		eCX
5A	POP		eDX
5B	POP		eBX
5C	POP		eSP
5D	POP		eBP
5E	POP		eSI
5F	POP		eDI
60	--
61	--
62	--
63	--
64	--
65	--
66	--
67	--
68	--
69	--
6A	--
6B	--
6C	--
6D	--
6E	--
6F	--
70	JO		Jb
71	JNO		Jb
72	JB		Jb
73	JNB		Jb
74	JZ		Jb
75	JNZ		Jb
76	JBE		Jb
77	JA		Jb
78	JS		Jb
79	JNS		Jb
7A	JPE		Jb
7B	JPO		Jb
7C	JL		Jb
7D	JGE		Jb
7E	JLE		Jb
7F	JG		Jb
80	GRP1	Eb	Ib
81	GRP1	Ev	Iv
82	GRP1	Eb	Ib
83	GRP1	Ev	Ib
84	TEST	Gb	Eb
85	TEST	Gv	Ev
86	XCHG	Gb	Eb
87	XCHG	Gv	Ev
88	MOV		Eb	Gb
89	MOV		Ev	Gv
8A	MOV		Gb	Eb
8B	MOV		Gv	Ev
8C	MOV		Ew	Sw
8D	LEA		Gv	M
8E	MOV		Sw	Ew
8F	POP		Ev
90	NOP
91	XCHG	eCX eAX
92	XCHG	eDX eAX
93	XCHG	eBX eAX
94	XCHG	eSP eAX
95	XCHG	eBP eAX
96	XCHG	eSI eAX
97	XCHG	eDI eAX
98	CBW
99	CWD
9A	CALL	Ap
9B	WAIT
9C	PUSHF
9D	POPF
9E	SAHF
9F	LAHF
A0	MOV		AL	Ob
A1	MOV		eAX	Ov
A2	MOV		Ob	AL
A3	MOV		Ov	eAX
A4	MOVSB
A5	MOVSW
A6	CMPSB
A7	CMPSW
A8	TEST	AL	Ib
A9	TEST	eAX	Iv
AA	STOSB
AB	STOSW
AC	LODSB
AD	LODSW
AE	SCASB
AF	SCASW
B0	MOV		AL	Ib
B1	MOV		CL	Ib
B2	MOV		DL	Ib
B3	MOV		BL	Ib
B4	MOV		AH	Ib
B5	MOV		CH	Ib
B6	MOV		DH	Ib
B7	MOV		BH	Ib
B8	MOV		eAX	Iv
B9	MOV		eCX	Iv
BA	MOV		eDX	Iv
BB	MOV		eBX	Iv
BC	MOV		eSP	Iv
BD	MOV		eBP	Iv
BE	MOV		eSI	Iv
BF	MOV		eDI	Iv
C0	--
C1	--
C2	RET		Iw
C3	RET
C4	LES		Gv	Mp
C5	LDS		Gv	Mp
C6	MOV		Eb	Ib
C7	MOV		Ev	Iv
C8	--
C9	--
CA	RETF	Iw
CB	RETF
CC	INT		3
CD	INT		Ib
CE	INTO
CF	IRET
D0	GRP2	Eb	1
D1	GRP2	Ev	1
D2	GRP2	Eb	CL
D3	GRP2	Ev	CL
D4	AAM		I0
D5	AAD		I0
D6	--
D7	XLAT
D8	--
D9	--
DA	--
DB	--
DC	--
DD	--
DE	--
DF	--
E0	LOOPNZ	Jb
E1	LOOPZ	Jb
E2	LOOP	Jb
E3	JCXZ	Jb
E4	IN		AL	Ib
E5	IN		eAX	Ib
E6	OUT		Ib	AL
E7	OUT		Ib	eAX
E8	CALL	Jv
E9	JMP		Jv
EA	JMP		Ap
EB	JMP		Jb
EC	IN		AL	DX
ED	IN		eAX	DX
EE	OUT		DX	AL
EF	OUT		DX	eAX
F0	LOCK
F1	--
F2	REPNZ
F3	REPZ
F4	HLT
F5	CMC
F6	GRP3a	Eb
F7	GRP3b	Ev
F8	CLC
F9	STC
FA	CLI
FB	STI
FC	CLD
FD	STD
FE	GRP4	Eb
FF	GRP5	Ev"""

map = dict()
for line in strmap.split("\n"):
	item = line.split("\t")
	map[item[0]] = item[1]
	for i in range(2,len(item)):
		map[item[0]] += " " + item[i]
	
# HP-NNM B.07.53 allowed characters: goodchars.txt
allowed = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x31\x32\x33\x34\x35\x36\x37\x38 \x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c \x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d \x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e \x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f")

for byte in allowed:
	strbyte = ("%02X" % ord(byte))
	print "[+] \\x" + strbyte + " => " + map[strbyte]
