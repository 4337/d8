#include <windows.h>
#include <stdio.h>

#include "disasm.h"

/*
*
*  @based on intel manual and bpde 
* **********************************************
*  we dont support two and there bytes instruction (mostly SMID||privileged instruction)
*  two bytes instruction are proceded by extend_byte_prefix 0Fh
*  so this is enough to get correct length (prefix detection)
*  *********************************************
*  First of all ! It's a length disasm not a real disasm *
*  if you want disasm for use in polly/metha/morph code u must at least
*  add more flags in _OC_FLAGS (eg. not only length of imm/reg/mem/ptr opperand but types and so on)
* 
*  This code was created as a poc && for epo technique usgae in that case we dont need details about instruction
*  only basic infos (length && type)
*/
static int _OC_FLAGS[] = {
                          OC_MODRM | OC_DIR,                   /*0x00*/
                          OC_MODRM | OC_DIR,                   /*0x01*/
                          OC_MODRM | OC_DIR,                   /*0x02*/
                          OC_MODRM | OC_DIR,                   /*0x03*/
                          OC_1_B_OPP,                          /*0x04*/
                          OC_2_4_B_OPP,                        /*0x05*/
                          0,                                   /*0x06 push es*/
                          0,                                   /*0x07 pop es*/
                          OC_MODRM | OC_DIR,                   /*0x08*/
                          OC_MODRM | OC_DIR,                   /*0x09*/
                          OC_MODRM | OC_DIR,                   /*0x0a*/
                          OC_MODRM | OC_DIR,                   /*0x0b*/
                          OC_1_B_OPP,                          /*0x0c*/
                          OC_2_4_B_OPP,                        /*0x0d*/
                          0,                                   /*0x0e*/
                          0,                                   /*0x0f*/
                          OC_MODRM | OC_DIR,                   /*0x10*/
                          OC_MODRM | OC_DIR,                   /*0x11*/
                          OC_MODRM | OC_DIR,                   /*0x12*/
                          OC_MODRM | OC_DIR,                   /*0x13*/
                          OC_1_B_OPP,                          /*0x14*/
                          OC_2_4_B_OPP,                        /*0x15*/
                          0,                                   /*0x16*/
                          0,                                   /*0x17*/
                          OC_MODRM | OC_DIR,                   /*0x18*/
                          OC_MODRM | OC_DIR,                   /*0x19*/
                          OC_MODRM | OC_DIR,                   /*0x1A*/
                          OC_MODRM | OC_DIR,                   /*0x1B*/
                          OC_1_B_OPP,                          /*0x1C*/
                          OC_2_4_B_OPP,                        /*0x1D*/
                          0,                                   /*0x1E*/
                          0,                                   /*0x1F*/
                          OC_MODRM | OC_DIR,                   /*0x20*/
                          OC_MODRM | OC_DIR,                   /*0x21*/
                          OC_MODRM | OC_DIR,                   /*0x22*/
                          OC_MODRM | OC_DIR,                   /*0x23*/
                          OC_1_B_OPP,                          /*0x24*/
                          OC_2_4_B_OPP,                        /*0x25*/
                          0,
                          0,
                          OC_MODRM | OC_DIR,                     /*0x28*/
                          OC_MODRM | OC_DIR,                     /*0x29*/
                          OC_MODRM | OC_DIR,                     /*0x2a*/
                          OC_MODRM | OC_DIR,                     /*0x2b*/
                          OC_1_B_OPP,                            /*0x2c*/
                          OC_2_4_B_OPP,                          /*0x2d*/
                          0,
                          0,
                          OC_MODRM | OC_DIR,                      /*0x30*/
                          OC_MODRM | OC_DIR,                      /*0x31*/
                          OC_MODRM | OC_DIR,                      /*0x32*/
                          OC_MODRM | OC_DIR,                      /*0x33*/
                          OC_1_B_OPP,                             /*0x34*/
                          OC_2_4_B_OPP,                           /*0x35*/
                          0,
                          0,
                          OC_MODRM | OC_DIR,                       /*0x38*/
                          OC_MODRM | OC_DIR,                       /*0x39*/
                          OC_MODRM | OC_DIR,                       /*0x3a*/
                          OC_MODRM | OC_DIR,                       /*0x3b*/
                          OC_1_B_OPP,                              /*0x3c*/
                          OC_2_4_B_OPP,                            /*0x3d*/
                          0,
                          0,
                          OC_REG_3LAST_BITS,                      /*0x40*/
                          OC_REG_3LAST_BITS,                      /*0x41*/
                          OC_REG_3LAST_BITS,                      /*0x42*/
                          OC_REG_3LAST_BITS,                      /*0x43*/
                          OC_REG_3LAST_BITS,                      /*0x44*/
                          OC_REG_3LAST_BITS,                      /*0x45*/
                          OC_REG_3LAST_BITS,                      /*0x46*/
                          OC_REG_3LAST_BITS,                      /*0x47*/
                          OC_REG_3LAST_BITS,                      /*0x48*/
                          OC_REG_3LAST_BITS,                      /*0x49*/
                          OC_REG_3LAST_BITS,                      /*0x4A*/
                          OC_REG_3LAST_BITS,                      /*0x4B*/
                          OC_REG_3LAST_BITS,                      /*0x4C*/
                          OC_REG_3LAST_BITS,                      /*0x4D*/
                          OC_REG_3LAST_BITS,                      /*0x4E*/
                          OC_REG_3LAST_BITS,                      /*0x4f*/
                          OC_REG_3LAST_BITS,                      /*0x50*/
                          OC_REG_3LAST_BITS,                      /*0x51*/
                          OC_REG_3LAST_BITS,                      /*0x52*/
                          OC_REG_3LAST_BITS,                      /*0x53*/
                          OC_REG_3LAST_BITS,                      /*0x54*/
                          OC_REG_3LAST_BITS,                      /*0x55*/
                          OC_REG_3LAST_BITS,                      /*0x56*/
                          OC_REG_3LAST_BITS,                      /*0x57*/
                          OC_REG_3LAST_BITS,                      /*0x58*/
                          OC_REG_3LAST_BITS,                      /*0x59*/
                          OC_REG_3LAST_BITS,                      /*0x5A*/
                          OC_REG_3LAST_BITS,                      /*0x5B*/
                          OC_REG_3LAST_BITS,                      /*0x5c*/
                          OC_REG_3LAST_BITS,                      /*0x5d*/
                          OC_REG_3LAST_BITS,                      /*0x5e*/
                          OC_REG_3LAST_BITS,                      /*0x5f*/
                          0,                                      /*0x60 pushad*/
                          0,                                      /*0x61 popad*/
                          OC_MODRM | OC_4_B_OPP,                  /*0x62 bound*/
                          OC_MODRM,                               /*0x63*/
                          0,
                          0,
                          0,
                          0,
                          OC_4_B_OPP,                             /*0x68*/
                          OC_MODRM | OC_4_B_OPP,                  /*0x69*/
                          OC_1_B_OPP,                             /*0x6a*/
                          OC_MODRM | OC_1_B_OPP,                  /*0x6b*/
                          OC_UNSUPPORTED,                          /*0x6c pi*/
                          OC_UNSUPPORTED,                         /*0x6d pi*/
                          OC_UNSUPPORTED,                         /*0x6e pi*/
                          OC_UNSUPPORTED,                         /*0x6f pi*/
                          OC_1_B_OPP,                             /*0x70 one byte offset jxx (jo)*/
                          OC_1_B_OPP,                             /*0x71 jno*/
                          OC_1_B_OPP,                             /*0x72 jb */
                          OC_1_B_OPP,                             /*0x73 jnb*/
                          OC_1_B_OPP,                             /*0x74 je*/
                          OC_1_B_OPP,                             /*0x75 jne/z*/
                          OC_1_B_OPP,                             /*0x76*/
                          OC_1_B_OPP,                             /*0x77*/
                          OC_1_B_OPP,                             /*0x78*/
                          OC_1_B_OPP,                             /*0x79*/
                          OC_1_B_OPP,                             /*0x7A*/
                          OC_1_B_OPP,                             /*0x7B*/
                          OC_1_B_OPP,                             /*0x7C*/
                          OC_1_B_OPP,                             /*0x7D*/
                          OC_1_B_OPP,                             /*0x7E*/
                          OC_1_B_OPP,                             /*0x7F*/
                          OC_OP_EXTENSION | OC_MODRM | OC_1_B_OPP, /*0x80*/
                          OC_OP_EXTENSION | OC_MODRM | OC_2_4_B_OPP, /*0x81*/
                          OC_OP_EXTENSION | OC_MODRM | OC_1_B_OPP, /*0x82*/
                          OC_OP_EXTENSION | OC_MODRM | OC_2_4_B_OPP, /*0x83*/
                          OC_MODRM | OC_DIR,  /*0x84*/
                          OC_MODRM | OC_DIR,  /*0x85*/
                          OC_MODRM | OC_DIR,  /*0x86*/
                          OC_MODRM | OC_DIR,  /*0x87*/
                          OC_MODRM | OC_DIR,  /*0x88*/
                          OC_MODRM | OC_DIR,  /*0x89*/
                          OC_MODRM | OC_DIR,  /*0x8a*/
                          OC_MODRM | OC_DIR,  /*0x8b*/
                          OC_MODRM,                                /*0x8c mov x,segment_descriptor/reg*/
                          OC_MODRM,   /*0x8d*/
                          OC_MODRM | OC_DIR, /*0x8e*/
                          OC_MODRM, /*0x8f*/
                          0,                                       /*0x90 nop*/
                          0,                                       /*0x91*/
                          0,                                       /*0x92*/
                          0,                                       /*0x93*/
                          0,                                       /*0x94*/
                          0,                                       /*0x95*/
                          0,                                       /*0x96*/
                          0,                                       /*0x97*/
                          0,                                       /*0x98 cwde*/
                          0,                                       /*0x99 cdq*/
                          OC_6_B_OPP,                              /*0x9a*/
                          0,
                          0,                                       /*0x9c pushfd*/
                          0,                                       /*0x9d popfd*/
                          0,                                       /*0x9e*/
                          0,                                       /*0x9f*/
                          OC_4_B_OPP | OC_DIR,                     /*0xa0*/
                          OC_4_B_OPP | OC_DIR,                     /*0xa1*/
                          OC_4_B_OPP | OC_DIR,                     /*0xa2*/
                          OC_4_B_OPP | OC_DIR,                     /*0xa3*/
                          0,                                       /*0xa4*/
                          0,                                       /*0xa5*/
                          0,                                       /*0xa6*/
                          0,                                       /*0xa7*/
                          OC_1_B_OPP,                              /*0xa8*/
                          OC_4_B_OPP,                              /*0xa9*/
                          0,                                       /*0xaa stosb*/
						  0,                                       /*0xab stosd*/
						  0,                                       /*0xac lods*/
						  0,                                       /*0xad*/
						  0,                                       /*0xae*/
						  0,                                       /*0xaf*/
						  OC_1_B_OPP,                              /*0xb0*/
						  OC_1_B_OPP,                              /*0xb1*/
						  OC_1_B_OPP,                              /*0xb2*/
						  OC_1_B_OPP,                              /*0xb3*/
						  OC_1_B_OPP,                              /*0xb4*/
						  OC_1_B_OPP,                              /*0xb5*/
						  OC_1_B_OPP,                              /*0xb6*/
						  OC_1_B_OPP,                              /*0xb7*/
						  OC_4_B_OPP,                              /*0xb8*/
						  OC_4_B_OPP,                              /*0xb9*/
						  OC_4_B_OPP,                              /*0xba*/
						  OC_4_B_OPP,                              /*0xbb*/
						  OC_4_B_OPP,                              /*0xbc*/
						  OC_4_B_OPP,                              /*0xbd*/
						  OC_4_B_OPP,                              /*0xbe*/
						  OC_4_B_OPP,                              /*0xbf*/
						  OC_OP_EXTENSION | OC_MODRM | OC_1_B_OPP, /*0xc0*/
						  OC_OP_EXTENSION | OC_MODRM | OC_1_B_OPP, /*0xc1*/
						  OC_2_B_OPP,                              /*0xc2*/
						  0,                                       /*0xc3*/
						  OC_MODRM,                                /*0xc4*/
						  OC_MODRM,                                /*0xc5*/
						  OC_1_B_OPP | OC_MODRM,                   /*0xc6*/
						  OC_2_4_B_OPP | OC_MODRM,                 /*0xc7*/
						  OC_3_B_OPP,                              /*0xc8*///2,1
						  0,                                       /*0xc9*/
						  OC_2_B_OPP,                              /*0xca*/
						  0,
						  0,
						  OC_1_B_OPP,                              /*0xcd*/
						  0,
						  0,
						  OC_MODRM | OC_OP_EXTENSION,              /*0xd0*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xd1*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xd2*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xd3*/
						  OC_1_B_OPP,                              /*0xd4*/
						  OC_1_B_OPP,                              /*0xd5*/
						  0,
						  0,
						  OC_MODRM,                                /*0xd8*/
						  OC_MODRM,                                /*0xd9*/
						  OC_MODRM,                                /*0xda*/
						  OC_MODRM,                                /*0xdb*/
						  OC_MODRM,                                /*0xdc*/
						  OC_MODRM,                                /*0xdd*/
						  OC_MODRM,                                /*0xde*/
						  OC_MODRM,                                /*0xdf*/
						  OC_1_B_OPP,                              /*0xe0*/
						  OC_1_B_OPP,                              /*0xe1*/
						  OC_1_B_OPP,                              /*0xe2*/
						  OC_1_B_OPP,                              /*0xe3*/
						  OC_1_B_OPP,                              /*0xe4*/
						  OC_1_B_OPP,                              /*0xe5*/
						  OC_1_B_OPP,                              /*0xe6*/
						  OC_1_B_OPP,                              /*0xe7*/
						  OC_4_B_OPP,                              /*0xe8*/
						  OC_4_B_OPP,                              /*0xe9*/
						  OC_6_B_OPP,                              /*0xea*///2:4
						  OC_1_B_OPP,                              /*0xeb*/
						  0,                                       /*0xec in*/
						  0,                                       /*0xed*/
						  0,                                       /*0xee*/
						  0,                                       /*0xef*/
						  0,                                       /*0xf0 lock:*/
						  0,                                       /*0xf1 INT1*/
						  0,
						  0,
						  0,                                       /*0xf4*/
						  0,                                       /*0xf5*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xf6*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xf7*/
						  0,                                       /*0xf8 clc*/
						  0,
						  0,                                       /*0xfa*/
						  0,
						  0,
						  0,                                       /*0xfd*/
						  OC_MODRM | OC_OP_EXTENSION,              /*0xfe*/
						  OC_MODRM | OC_OP_EXTENSION               /*0xff*/
                         };
                         
BYTE __stdcall oc_is_prefix(OPCODE* oc) {
	 switch(*oc->ip) {
	 	    case  OC_OPERAND_SIZE_PREFIX:
	 	    case  OC_ADDRESS_SIZE_PREFIX:
	        case  OC_LOCK_PREFIX:
	        case  OC_REP_NENZ_PREFIX:
	        case  OC_REP_EZ_PREFIX:
	        case  OC_CS_SEG_PREFIX:
	        case  OC_SS_SEG_PREFIX:
	        case  OC_DS_SEG_PREFIX:
	        case  OC_ES_SEG_PREFIX:
	        case  OC_FS_SEG_PREFIX:
	        case  OC_GS_SEG_PREFIX:
	        case  OC_OP_EXPANSION_PREFIX:
	              oc->prefixes.prefix[oc->prefixes.count] = *oc->ip;
	              ++oc->prefixes.count;
	              return *oc->ip;
	        break;
	  }
	 return OC_NO_PREFIX;
}

VOID __stdcall oc_init(OPCODE* oc,BYTE* code) {
	 oc->ip               = code;
	 oc->length.op_len    = 0;
	 oc->length.total_len = 0;
	 oc->opcode           = *code;
	 oc->prefixes.count   = 0;
	 oc->OPERANDS.count   = 0;
	 oc->flag             = 0;
	 oc->DS.status        = 0;	
	 oc->reg1             = 0;
	 oc->reg2             = 0;
	 memset(&oc->prefixes.prefix,0,OC_MAX_PREFIX + 1);
}

BOOL  __stdcall oc_has_size_prefix(OPCODE* oc) {
	  register INT i;
	  for(i=0;i<oc->prefixes.count;i++) {
	  	  if(OC_OPERAND_SIZE_PREFIX == oc->prefixes.prefix[i]) {
			 return TRUE;
	      }
	  }
	  return FALSE;
}

VOID  __stdcall oc_getopp(OPCODE* oc,UCHAR size,DWORD type) {
	 oc->OPERANDS.operands[oc->OPERANDS.count].op_type = type;
	 oc->OPERANDS.operands[oc->OPERANDS.count].size    = size;
	 if(size == 1) oc->OPERANDS.operands[oc->OPERANDS.count].op = *((BYTE*)(oc->ip + 1));
	 if(size == 2) oc->OPERANDS.operands[oc->OPERANDS.count].op = *((WORD*)(oc->ip + 1));
	 if(size == 4) oc->OPERANDS.operands[oc->OPERANDS.count].op = *((DWORD*)(oc->ip + 1));
	 ++oc->OPERANDS.count;
	 oc->ip += size;   //ip on next instruction
	 oc->length.op_len += size;  //len += op size 
}

BYTE* __stdcall oc_decode(OPCODE* oc) {
	  
	  BYTE prefix;
	  
	  oc->flag           = 0;
	  oc->length.op_len  = 0;
	  oc->OPERANDS.count = 0;
	  
	  oc->opcode = *oc->ip;
	  
	  if((prefix = oc_is_prefix(oc)) != OC_NO_PREFIX) {
	  	 if(oc->prefixes.count > OC_MAX_PREFIX) {
		    return (BYTE*)OC_INSTRUCTION_ERROR;
	     } else {
	       if(prefix == OC_OP_EXPANSION_PREFIX) {
		      ++oc->ip;
		      ++oc->length.op_len;
		      oc->opcode = *oc->ip;
		   }
		   ++oc->length.op_len;
		 }
	  } else { 	
	          oc->flag   = _OC_FLAGS[*oc->ip];
              
		      if(oc->flag == 0) {
	  	         oc->length.op_len = 1;
	          } else if(oc->flag & OC_UNSUPPORTED) {  /*unsupported*/
	                    return (BYTE*)OC_INSTRUCTION_ERROR;
              } else {
              	     ++oc->length.op_len;
              	     
      	             if(oc->flag & OC_DIR) {	
      	                oc->DS.dx_bit = oc->opcode & 0x02;
      	                oc->DS.size   = oc->opcode & 0x01;
      	                oc->DS.status = OC_HAS_DIR;  
			          } else if(oc->flag & OC_REG_3LAST_BITS) {
      	    	                oc->reg1 = oc->opcode & 0x07;
      	    	                oc->reg2 = OC_REG2_UNUSED;
			          } 
			
			          if(oc->flag & OC_MODRM) {
			             BOOL has_sib = FALSE;
			   
	  	                 ++oc->ip;               /*ip=ModRm*/
	  	                 ++oc->length.op_len;    /*op_len + 1*/
	  	       
			             oc->modrm.mod = (*oc->ip & 0xC0) >> 0x06;
			             oc->modrm.reg = (*oc->ip & 0x38) >> 0x03;
			             oc->modrm.rm  =  *oc->ip & 0x07;
			             oc->addr_mode =  *oc->ip & 0x3F  << 0x06;
			   
		                 if( ((oc->modrm.mod == 0x00) || (oc->modrm.mod == 0x01) ||
						     (oc->modrm.mod == 0x02)) && (oc->modrm.rm == 0x04)) {
			             	   oc->sib.scale = (*(oc->ip + 1) & 0xC0) >> 6;    //2b
		                       oc->sib.index = (*(oc->ip + 1) & 0x38) >> 3;    //3b
		                       oc->sib.base  =  *(oc->ip + 1) & 0x07;          //3b
			       	           has_sib = TRUE;
				         }
			    
			             if(oc->flag & OC_OP_EXTENSION) {
			   	            oc->reg1 = oc->modrm.rm;   
			   	            if(oc->modrm.reg == 0x00) oc->reg2 = OC_REG2_IMM;
			   	            //...
			             }  
			   
			             if(oc->addr_mode == OC_MOD_REG_INDIRECT) {  
			                /*printf(
							       "Mod Reg Indirect opcode: 0x%x\r\n",
							        oc->opcode
							      );*/
			   	            if(oc->modrm.rm == 0x05) {     /*32-bit Displacement-Only Mode*/
			   	               oc_getopp(oc,4,OC_OP_OPP32);	
						    } else if(has_sib == TRUE) {
						              ++oc->ip;            /*ip on sib*/
									  ++oc->length.op_len;	//start from 0
									  //printf(" reg indir sib oc:0%x len: %d ",*oc->ip,oc->length.op_len);
									  if(oc->sib.base == 0x05) { /*Dispacement Only id mod == 00*/
									  	 oc_getopp(oc,4,OC_OP_OPP32);
									  }
							}   
			             }
			   
			             if(oc->addr_mode == OC_MOD_1BYTE_DISPLACEMENT) {
			   	            if(has_sib == TRUE) {
					           ++oc->ip;   //ip on sib
					           ++oc->length.op_len;
			                } 
			                oc_getopp(oc,1,OC_OP_OPP8);  //oc->ip must ptr on first byte before opperand 
	      	              }
			   
			              if(oc->addr_mode == OC_MOD_4BYTE_DISPLACEMENT) {
			   	             UCHAR size = (oc_has_size_prefix(oc) == TRUE) ? 2 : 4;
			   	             DWORD type = (size == 2) ? OC_OP_OPP16 : OC_OP_OPP32;
			   	             if(has_sib == TRUE) {
			   	  	            ++oc->ip;
			   	  	            ++oc->length.op_len;
				             }
				             oc_getopp(oc,size,type);
			              }
			   
			              if(oc->addr_mode == OC_MOD_REG_ADDRESSING) {
			              	 /*printf(
							        " Reg Addressing mode opcode: 0x%x len: %d ",
							         oc->opcode,
							         oc->length.op_len
							       ); */
			   	             /*oc->flag = oc->flag & ~( OC_1_B_OPP | OC_2_4_B_OPP | OC_4_B_OPP | 
							                          OC_6_B_OPP | OC_2_B_OPP | OC_3_B_OPP );*/
							 oc->reg1 = oc->modrm.reg;
			   	             oc->reg2 = oc->modrm.rm;    
			              }  	  	
		               } 

		 	           if(oc->flag & OC_1_B_OPP) {
			              oc_getopp(oc,1,OC_OP_OPP8);
		               }  
			
		 	           if(oc->flag & OC_2_4_B_OPP) {
			              UCHAR size = (oc_has_size_prefix(oc) == TRUE) ? 2 : 4;
			              DWORD type = (size == 2) ? OC_OP_OPP16 : OC_OP_OPP32;
			              oc_getopp(oc,size,type);
			           }
			
		      	       if(oc->flag & OC_4_B_OPP) {	
			              oc_getopp(oc,4,OC_OP_OPP32);
			           }
			
			           if(oc->flag & OC_6_B_OPP) {   //2:4
			              oc_getopp(oc,2,OC_OP_OPP16);
			              oc_getopp(oc,4,OC_OP_OPP32);
			            }
			
			            if(oc->flag & OC_3_B_OPP) {  //2,1
			               oc_getopp(oc,2,OC_OP_OPP16);
			               oc_getopp(oc,1,OC_OP_OPP8);
			            }
	          }
	          memset(&oc->prefixes.prefix,0,OC_MAX_PREFIX + 1);
	          oc->prefixes.count = 0;
      }

	 ++oc->ip; 
	 oc->length.total_len += oc->length.op_len;
	 return oc->ip;
} 

