#include "hash.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "common.h"
#include "interface.h"
#include <stdlib.h>

bool next_nonce(char* c){
    if(c[0]=='\0'){
        return false;
    }
    
    //if end of range, wrap around and increment next 'digit'
    if(c[0]=='9'){
        c[0]='a';
		//the compiler may generate an 'above array bounds' warning here, which can be safely ignored
		if (next_nonce(&c[1]))
            return true;
        c[0]='\0';
        return false;
    }   

    //jump boundaries
    if(c[0]=='z')
        c[0]='A';
    else if(c[0]=='Z')
        c[0]='0';
    else
        c[0]++;

    return true;
}

bool check_hash(char* hash){
    //check if first n-characters are zero
    for(int i=0;i<LEADING_ZEROES;i++)
		//Note: each 'char' of 8 bits contains 2 hex characters representing 4 bits each.
		//Hence all this bit shuffling
		if ((hash[i>>1]&(0xF0>>((i&0x1)<<2)))!=0)
            return false;
    return true;
}


void benchmark(void){
    // + 1 for termination '\0'
    char input[INPUT_SIZE+NONCE_SIZE+1];
    
    //position of repeated string in input
    char* base = &(input[NONCE_SIZE]);

    //holder for the nonce
    char nonce[NONCE_SIZE+1];

    while(true){
    
        //request new input from server (should be successful, o.w. just retry)
        while(!requestInput(base));

        //init nonce with 'a'*NONCE_SIZE
        for(int i=0;i<NONCE_SIZE;i++)
            nonce[i]='a';
        nonce[NONCE_SIZE]='\0';
        
        //test all possible nonces 
        do{
            //copy nonce into input
            for(int i=0;i<NONCE_SIZE;i++)
                input[i]=nonce[i];

            //64 chars + '\0' for binary output
            char output_hash[64+1];
            
            //calculate hash
            hash((unsigned char*)output_hash, (unsigned char*)input, strlen(input));

            //check if hash matches desired output
            //if so, stop the search
            if (check_hash(output_hash))
                break;

        }while(next_nonce(nonce));

        //if we reach here, either we found a matching nonce, or we exhaustively tested all nonces

        //validate with server
        validateHash(base, nonce);
    }

}

int main(int argc, char *argv[]){
    
   	if ((argc==2) && (strcmp(argv[1],"-benchmark")==0) ){
        benchmark();
    }
    
    else if (argc==4){
        //64 chars for 512bit output
        unsigned char output_hash[64+1];
        
        char* nonce = argv[1];
        int nonce_size=strlen(nonce);
        char* baseInput = argv[2];
        int baseInputSize=strlen(baseInput);
        int muliplier=atoi(argv[3]);

        //nonce first and append input string desired number of times
        char* input = (char*)malloc(sizeof(char)*(baseInputSize*muliplier+nonce_size+1));
        for(int i=0;i<nonce_size;i++)
            input[i]=nonce[i];
        char* repeat_ptr=&(input[nonce_size]);
        for(int j=0;j<muliplier;j++)
            for(int i=0;i<baseInputSize;i++)
                repeat_ptr[j*baseInputSize+i]=baseInput[i];
        input[baseInputSize*muliplier+nonce_size]='\0';

        //do hash
        hash(output_hash, (unsigned char*)input, baseInputSize*muliplier+nonce_size );
        
        for(int i=0;i<64;i++)
			printf("%02X",output_hash[i]);

        free(input);

    }else{
        printf("usage: %s nonce (string) input(string) multiplier(int)\n", argv[0]);
        printf("------------OR-------------\n");
        printf("usage: %s -benchmark\n", argv[0]);
    }

	return 0;
}

