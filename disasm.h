#ifndef OC_DISASM_H
#define OC_DISASM_H

#define OC_MAX_OPERANDS 3 /* max 3 opperands we dont need more 3 is enough eg. imul a,b,c */

#define OC_MODRM          0x00000001  /*got modrm*/
#define OC_DIR            0x00000010  /*got direction bit*/ 
#define OC_1_B_OPP        0x00000100  /*got 1 byte opperand*/
#define OC_2_4_B_OPP      0x00001000  /*got 4 or 2 bytes opperand deoending on prefix*/
#define OC_REG_3LAST_BITS 0x01000000  /*reg at 3 last bits  2 or 4 bytes [ax/eax] depend on size prefix*/
#define OC_4_B_OPP        0x10000000  /*ptr [MMEEMM44] */
#define OC_REG_2_B        0x00000002  /* 16bits register */
#define OC_OP_EXTENSION   0x00000020  /* reg field modrm is op extension*/
#define OC_6_B_OPP        0x00000200  /* far ptr */
#define OC_2_B_OPP        0x00002000  /* word opp*/
#define OC_3_B_OPP        0x00020000  /* 3 bytes opperand word,byte*/
#define OC_UNSUPPORTED    ~(OC_MODRM | OC_DIR |\
                            OC_1_B_OPP | OC_2_4_B_OPP |\
			    OC_REG_3LAST_BITS | OC_4_B_OPP |\
			    OC_REG_2_B | OC_OP_EXTENSION |\
			    OC_6_B_OPP | OC_2_B_OPP |\
			    OC_3_B_OPP)/* unsupported */

#define OC_OP_OPP8  0x00000001
#define OC_OP_OPP32 0x00000010
#define OC_OP_OPP16 0x00000100

typedef struct {
	    DWORD   op;
	    DWORD   op_type;   /* imm,reg,mem,rel,...*/
	    DWORD   size;
}OPERAND,*POPERAND;

#define OC_MOD_REG_INDIRECT       0x00
#define OC_MOD_1BYTE_DISPLACEMENT 0x40
#define OC_MOD_4BYTE_DISPLACEMENT 0x80
#define OC_MOD_REG_ADDRESSING     0xC0

typedef struct {
        BYTE   mod:2;
   	BYTE   reg:3;
	BYTE   rm:3;
}MODRM,*PMODRM;

typedef struct {
	BYTE   scale:2;
	BYTE   index:3;
	BYTE   base:3;
	DWORD  offset;
}SIB,*PSIB;

typedef struct {
	UCHAR op_len;
	DWORD total_len;
}LENGTH,*PLENGTH;

#define OC_MAX_PREFIX 3

typedef struct {
	BYTE   prefix[OC_MAX_PREFIX + 1];
        UCHAR  count;
}PREFIXES,*PPREFIXES;

#define OC_NO_DIR_NO_SIZE 0x00
#define OC_HAS_DIR        0x3f

typedef struct {
	BYTE    opcode;
	INT     flag;
	struct {
		 OPERAND  operands[OC_MAX_OPERANDS];
		 UCHAR    count;
	}OPERANDS,*POPERANDS;
	PREFIXES prefixes;
        MODRM    modrm;     /* optional */       
        SIB      sib;       /* oprional */
        BYTE     addr_mode; /* optional OC_MOD_REG_INDIRECT 0x00 || OC_MOD_1BYTE_DISPLACEMENT 0x40 || OC_MOD_4BYTE_DISPLACEMENT 0x80 || OC_MOD_REG_ADDRESSING  0xC0 */   
        LENGTH   length;    /* opcode && tot length */
        BYTE*    ip;        /* instruction pointer */
        struct {
        	BYTE dx_bit:1; /*dir*/
        	BYTE size:1;   /*size*//*depend on prefix presence*/
        	BYTE status:6;
	}DS,*PDS;
	BYTE    reg1;
	BYTE    reg2;
}OPCODE,*POPCODE;

#define OC_NO_PREFIX            0x00

#define OC_OPERAND_SIZE_PREFIX  0x66  
#define OC_ADDRESS_SIZE_PREFIX  0x67

#define OC_LOCK_PREFIX          0xF0
#define OC_REP_NENZ_PREFIX      0xF2
#define OC_REP_EZ_PREFIX        0xF3

#define OC_CS_SEG_PREFIX        0x2E
#define OC_SS_SEG_PREFIX        0x36
#define OC_DS_SEG_PREFIX        0x3E
#define OC_ES_SEG_PREFIX        0x26
#define OC_FS_SEG_PREFIX        0x64
#define OC_GS_SEG_PREFIX        0x65

#define OC_OP_EXPANSION_PREFIX  0x0F

BYTE  __stdcall oc_is_prefix(OPCODE*);
VOID  __stdcall oc_init(OPCODE*,BYTE*);

#define OC_INSTRUCTION_ERROR    0xffffffff
#define OC_REG2_IMM             0x7F
#define OC_REG2_UNUSED          0x7E

BYTE* __stdcall oc_decode(OPCODE*);
VOID  __stdcall oc_getopp(OPCODE*,UCHAR,DWORD);
BOOL  __stdcall oc_has_size_prefix(OPCODE*);



#endif
