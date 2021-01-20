// Code based of of
// https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define f64(x) ((ROTL64(x,1) & ROTL64(x,8)) ^ ROTL64(x,2))
#define R64x2(x,y,k1,k2) (y^=f64(x), y^=k1, x^=f64(y), x^=k2)
#define ROTL64(x,r) (((x)<<(r)) | (x>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))

void Simon128256KeySchedule(uint64_t K[], uint64_t rk[]){
	uint64_t i, D=K[3], C=K[2], B=K[1], A=K[0];
	uint64_t c=0xfffffffffffffffcLL, z=0xfdc94c3a046d678bLL;

	for(i=0; i<64;){
		rk[i++]=A; A^=c^(z&1)^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1); z>>=1;
		rk[i++]=B; B^=c^(z&1)^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1); z>>=1;
		rk[i++]=C; C^=c^(z&1)^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1); z>>=1;
		rk[i++]=D; D^=c^(z&1)^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1); z>>=1;
	}

	rk[64]=A; A^=c^0^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1);
	rk[65]=B; B^=c^1^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1);
	rk[66]=C; C^=c^0^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1);
	rk[67]=D; D^=c^0^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1);
	rk[68]=A; rk[69]=B; rk[70]=C; rk[71]=D;
}

void SimpleSimon128256KeySchedule(uint64_t K[], uint64_t rk[], int option){
	uint64_t i, D=K[3], C=K[2], B=K[1], A=K[0];
    uint64_t c=0xfffffffffffffffcLL, z=0xfdc94c3a046d678bLL;

	if(option = 0){
		for(i=0; i<64;){
			rk[i++]=A; A^=c^(z&1)^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1); z>>=1;
			rk[i++]=B; B^=c^(z&1)^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1); z>>=1;
			rk[i++]=C; C^=c^(z&1)^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1); z>>=1;
			rk[i++]=D; D^=c^(z&1)^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1); z>>=1;
		}
	}
	else{
		for(i=0; i<64;){
            rk[i++]=A; A^=c^(z^1)^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1); z>>=1;
            rk[i++]=B; B^=c^(z^1)^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1); z>>=1;
            rk[i++]=C; C^=c^(z^1)^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1); z>>=1;
            rk[i++]=D; D^=c^(z^1)^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1); z>>=1;
        }
	}

    rk[64]=A; A^=c^0^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1);
    rk[65]=B; B^=c^1^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1);
    rk[66]=C; C^=c^0^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1);
    rk[67]=D; D^=c^0^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1);
    rk[68]=A; rk[69]=B; rk[70]=C; rk[71]=D;
}

void Simon128256Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[]){
	uint64_t i;

	Ct[0]=Pt[0]; Ct[1]=Pt[1];
	for(i=0;i<72;i+=2) R64x2(Ct[1],Ct[0],rk[i],rk[i+1]);
}

void Simon128256Decrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[]){
	int i;

	Pt[0]=Ct[0]; Pt[1]=Ct[1];
	for(i=71;i>=0;i-=2) R64x2(Pt[0],Pt[1],rk[i],rk[i-1]);
}

int main(int argc, char** argv){
	uint64_t Pt[2], Ct[2], K[4], rk[72];
	Pt[0] = 0x6d69732061207369;
	Pt[1] = 0x74206e69206d6f6f;
	K[3]  = 0x1f1e1d1c1b1a1918;
	K[2]  = 0x1716151413121110;
	K[1]  = 0x0f0e0d0c0b0a0908;
	K[0]  = 0x0706050403020100;

	Simon128256KeySchedule(K,rk);
	Simon128256Encrypt(Pt,Ct,rk);
	printf("simon cipher: %lx %lx\n", Ct[1], Ct[0]);

	Pt[0] = 0x6d69732061207369;
    Pt[1] = 0x74206e69206d6f6f;
    K[3]  = 0x1f1e1d1c1b1a1918;
    K[2]  = 0x1716151413121110;
    K[1]  = 0x0f0e0d0c0b0a0908;
    K[0]  = 0x0706050403020100;

	SimpleSimon128256KeySchedule(K,rk,1);
    Simon128256Encrypt(Pt,Ct,rk);
    printf("simple simon cipher: %lx %lx\n", Ct[1], Ct[0]);

	return 0;
}
