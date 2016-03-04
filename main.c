#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "disasm.h"

UCHAR test[] = {	 
                0x89,0x5C,0x24,0x08,
                0xE9,0x96,0xCE,0xFE,0xFF,
                0x8D,0x49,0x00,
                0x8B,0xD4,
                0x0F,0x34,
                0x8D,0xA4,0x24,0x00,0x00,0x00,0x00,
                0xEB,0x03,
				0x90,
				0x90,
                0x64,0xC7,0x05,0x00,0x00,0x00,0x00,0x45,0x43,0x42,0x41, //two operands
				0x90,
				0xF2,0xAE,
				0x90,
				0x90,
				0x81,0xF9,0xFF,0xFF,0x00,0x00,
				0x90,
				0x90,
				0x66,0xC7,0x44,0x24,0x08,0x42,0x41,
				0x90,
				0x66,0x89,0x0A,
				0x90,
				0x66,0x89,0x4A,0x02,
				0x3B,0x75,0x14,
				0x90,
				0x0B,0xFF,
                0x90,0x90,
                0xE8,0xC3,0x04,0x00,0x00,
                0x90,0x90,0x90,
				0xC1,0xC0,0x04,
				0x90,0x90,0x90,0x90,
				0xFF,0xD0,
				0x90,0x90,
				0xC7,0xC1,0xC0,0x04,0x8B,0xFF,  //one operand
				0x90,0x90,
			    0x3E,0x89,0x1C,0xC5,0x00,0x00,0x00,0x00,                         /*MOV DWORD PTR DS:[EAX*8],EBX //SIB only mode*/
                
				0x66,0x3E,0xC7,0x04,0xC5,0x00,0x00,0x00,0x00,0x42,0x41,          /*MOV WORD PTR DS:[EAX*8],4142 //sib only mode*/
                0x90,0x90,
                
                0x66,0xC7,0x04,0xBF,0x42,0x41,                            /* MOV WORD PTR DS:[EDI+EDI*4],4142 */
                0x90,0x90,
                0x8B,0x3C,0x3F,                                      /*MOV EDI,DWORD PTR DS:[EDI+EDI]*/
                0x90,
                0x3E,0x8B,0x3C,0x8D,0x00,0x00,0x00,0x00,                      /*    MOV EDI,DWORD PTR DS:[ECX*4] */
                
				0x90,0x90,0x90,0x90,
				0x90,0x90,0x90,0x90
		       };
		       
#define OC_JMP_REL1632  0xE9
#define OC_JMP_REL8     0xEB
#define OC_CALL_REL1632 0xE8

/* run this program using the console pauser or add your own getch, system("pause") or input loop */

int main(int argc, char *argv[]) {
	INT i = 0;
	OPCODE oc;
	BYTE*  oc_ret;
	oc_init(&oc,test);
	
     while(oc.length.total_len < sizeof(test)){
     	   oc_ret = oc_decode(&oc);
     	   if(oc_ret == (BYTE*)OC_INSTRUCTION_ERROR) {
     	   	  printf(
				     "!]. Unsupported instruction !\r\n"
				     "    oc->opcode : 0x%x\r\n",
				     oc.opcode
				    );
			 break;
		   }
		   printf(
		          "%02d]. oc.opcode:           0x%02x\r\n"
		          "     oc.length.op_len:    %d total_len: %d\r\n",
		          i,
		          oc.opcode,
		          oc.length.op_len,
		          oc.length.total_len
		         );
		    if(oc.prefixes.count > 0) {
		     	printf(
			           "     prefix:              TRUE\r\n"
			          );
		    }
		    if((oc.opcode == OC_JMP_REL1632) || (oc.opcode == OC_JMP_REL8)) {
		        printf(
			           "     !]. I Found JMP 0x%x\r\n"
			           "         at ip 0x%x\r\n"
			           "         op.size = %d\r\n",
			           oc.OPERANDS.operands[0].op,
			           oc.ip,
			           oc.OPERANDS.operands[0].size
			         );	
			}
			if(oc.opcode == OC_CALL_REL1632) {
			    printf(
			           "     !]. I Found CALL 0x%x\r\n"
			           "         at ip 0x%x\r\n"
			           "         op.size = %d\r\n",
			           oc.OPERANDS.operands[0].op,
			           oc.ip,
			           oc.OPERANDS.operands[0].size
			         );	
			}
           i++;
	 }	
	
	return 0;
}