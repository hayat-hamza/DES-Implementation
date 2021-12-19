//============================================================================
// Name        : 1700470.cpp
// Author      : hayat
// Version     :
// Copyright   : hayat
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iostream>

using namespace std;
#ifdef __GNUC__
#define __rdtsc __builtin_ia32_rdtsc
#else
#include <intrin.h>
#endif

/*
 * *****************************************************************
 * 								Enums and Definitions
 * *****************************************************************
 */
typedef unsigned long long u64;
enum SHOW_ME{ENCRYPT,DECRYPT };
enum permutation_choices{INITAIL_PERM,PC1,PC2,EXPANTION,DATA_PERM,FINAL};

/*
 * *****************************************************************
 * 							Function prototypes
 * *****************************************************************
 */
u64 read_des_input(const char *data);
void print(u64 cipher);
u64 permute(u64 input,int *choosen_permutation,int permutation,int in_bits);
u64 leftRotate(u64 n, unsigned int d);
u64 numberOfShifts(int round);
u64 encryptOrDecrypt(u64 plain_text,u64 key);
void keysGeneration(u64 key);

/*
 * *****************************************************************
 * 								Global Variables
 * *****************************************************************
 */
u64 key_array[16];
int flag;		//indicates encrypt or decrypt

int s[512] = { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ,
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ,

         10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ,
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ,
         2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ,
         12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ,
         4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ,
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 };

int initial_perm[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
                             60, 52, 44, 36, 28, 20, 12, 4,
                             62, 54, 46, 38, 30, 22, 14, 6,
                             64, 56, 48, 40, 32, 24, 16, 8,
                             57, 49, 41, 33, 25, 17, 9, 1,
                             59, 51, 43, 35, 27, 19, 11, 3,
                             61, 53, 45, 37, 29, 21, 13, 5,
                             63, 55, 47, 39, 31, 23, 15, 7 };

int final_perm[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25 };

int permutation_choice1[56] = { 57, 49, 41, 33, 25, 17, 9,
                     1, 58, 50, 42, 34, 26, 18,
                     10, 2, 59, 51, 43, 35, 27,
                     19, 11, 3, 60, 52, 44, 36,
                     63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                     14, 6, 61, 53, 45, 37, 29,
                     21, 13, 5, 28, 20, 12, 4 };


int permutation_choice2[48]= { 14, 17, 11, 24, 1, 5,
                         3, 28, 15, 6, 21, 10,
                         23, 19, 12, 4, 26, 8,
                         16, 7, 27, 20, 13, 2,
                         41, 52, 31, 37, 47, 55,
                         30, 40, 51, 45, 33, 48,
                         44, 49, 39, 56, 34, 53,
                         46, 42, 50, 36, 29, 32 };
int per[32] = { 16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25 };


int exp_d[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
                      6, 7, 8, 9, 8, 9, 10, 11,
                      12, 13, 12, 13, 14, 15, 16, 17,
                      16, 17, 18, 19, 20, 21, 20, 21,
                      22, 23, 24, 25, 24, 25, 26, 27,
                      28, 29, 28, 29, 30, 31, 32, 1 };

int main(int argc,char** argv)
{
	u64 cipher,plain_text, key;

	if (argc == 4)
	{
		if (strcmp("encrypt", argv[1]) == 0) {
			flag=ENCRYPT;
			plain_text= read_des_input(argv[2]);
			key = read_des_input(argv[3]);
			long long t1=__rdtsc();
			cipher=encryptOrDecrypt(plain_text,key);
			long long t2=__rdtsc();


			/*
			 * print function is used to display the cipher in hexadecimal
			 */
			print(cipher);
			cout<<"Cycles: "<<t2-t1<<endl;
		}
		else if (strcmp("decrypt", argv[1]) == 0) {
			flag=DECRYPT;
			cipher= read_des_input(argv[2]);
			key = read_des_input(argv[3]);
			long long t1=__rdtsc();
			plain_text=encryptOrDecrypt(cipher,key);
			long long t2=__rdtsc();

			print(plain_text);

			cout<<"Cycles: "<<t2-t1<<endl;
		}
    }

	system("PAUSE");

	return 0;
}

u64 read_des_input(const char *data)
{
	u64 ret=0;
	for(;;++data)
	{
		unsigned char dec =*data-'0';
		if(dec<10){
			ret=ret<<4|dec;
		}
		else
		{
			unsigned char upper =(*data&0xDF)-'A';
			if(upper>5)break;
			ret=ret<<4|upper+10;
		}
	}
	return ret;
}

u64 permute(u64 input,int *choosen_permutation,int permutation,int in_bits)
{
	u64 out=0;
	int out_bits;
	if(permutation==INITAIL_PERM)	out_bits=64;
	if(permutation==PC1)	out_bits=56;
	if(permutation==PC2)	out_bits=48;
	if(permutation==EXPANTION)	out_bits=48;
	if(permutation==DATA_PERM)	out_bits=32;
	if(permutation==FINAL)	out_bits=64;


	for (int i=0;i<out_bits;i++){
		out|=(input>>(in_bits-choosen_permutation[out_bits-1-i])&1)<<i;
	}
	return out;
}
u64 leftRotate(u64 n, unsigned int shifts)
{
    u64 x= ((n << shifts) | (n >> (28 - shifts)));
    return x;
}

void print(u64 cipher)
{
   u64 num, temp2, i = 1, j, r;
	num= cipher;
	char hex[50];
	temp2 = num;
	while (temp2 != 0)
	{
		r = temp2 % 16;
		if (r < 10)
			hex[i++] = r + 48;
		else
			hex[i++] = r + 55;
		temp2 = temp2 / 16;
	}
	cout<<"Cipher: ";
	for (j = i-1; j > 0; j--)
	{
		  cout << hex[j];
	}
	cout<<endl;
}

u64 numberOfShifts(int round){
	int shift_table[16] = { 1, 1, 2, 2,
								2, 2, 2, 2,
								1, 2, 2, 2,
								2, 2, 2, 1 };
	u64 out=shift_table[round];
	return out;
}

u64 encryptOrDecrypt(u64 plain_text,u64 key)
{

	u64 cipher;
	u64 data_left;
	u64 data_right;
	u64 data_right_expanded;
	u64 data_and_key_xor;
	u64 permutation_output;
	u64 new_right_data;
	u64 new_left_data;
	u64 new_combine;

	u64 data_after_i_permutation=permute(plain_text,initial_perm,INITAIL_PERM,64);		//do inital permutation
	/*
	 * generates all 16 rounds keys
	 */
	keysGeneration(key);
	/*
	 * then enter round 1
	 */
	 data_left = (data_after_i_permutation >>32)& 0x00000000FFFFFFFF;
	 data_right = data_after_i_permutation & 0x00000000FFFFFFFF;
	for(int round=0;round<16;round++){
		/*
		 * do expansion to right data
		 */
		 data_right_expanded=permute(data_right,exp_d,EXPANTION,32);
		if(flag==ENCRYPT)
		{
			/*
			 * xor data after exp and key after pc2
			 */
			 data_and_key_xor=(key_array[round]^data_right_expanded);
		}
		if(flag==DECRYPT)
		{
			/*
			 * xor data after exp and key after pc2 and inverse key
			 */

			 data_and_key_xor=(key_array[15-round]^data_right_expanded);
		}

		/*
		 * s-box
		 */
		u64 result = 0;
		int box[64];
		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 64; j++) {
				box[j] = s[j + (i * 64)];
			}
			u64	idx = data_and_key_xor >> (7 - i) * 6 & 0x3F; //get the index
			idx = idx >> 1 & 15 | (idx & 1) << 4 | idx & 0x20; //reorder bits
			result |= box[idx] << (7 - i) * 4;
		}

		/*
		 * permutation after xor then f is finished
		 */
		 permutation_output=permute(result,per,DATA_PERM,32);
		/*
		 *xor left data with permutation_output which is function output
		 */

		 new_right_data=permutation_output^data_left;
		 new_left_data=data_right;
		 new_combine=((new_left_data<<32)&0XFFFFFFFF00000000)|(new_right_data&0X00000000FFFFFFFF);
		/*
		 * before next round i want input of rotate left to be equal to output of last round
		 * we want last left to equal last right and right equal left
		 */


		data_left =  new_left_data;
		data_right =new_right_data;

	}
	u64 temp = data_right;
	data_right = data_left;
	data_left = temp;
	u64 concateation = (data_right & 0x00000000FFFFFFFF) | ((data_left << 32) & 0xFFFFFFFF00000000);

	cipher = permute(concateation,final_perm,FINAL,64);

	return cipher;

}

void keysGeneration(u64 key)
{
	u64 key_left;
	u64 key_right;
	u64 key_left_after_rotate;
	u64 key_right_after_rotate;
	u64 combine_key;
	u64 key_after_choice2;
	u64 key_arr_reversed[16];		//used in case of decryption
	u64 key_after_choice1=permute(key,permutation_choice1,PC1,64);		//do permu choice 1
	/*
	 * split key in half
	 */
	key_left = (key_after_choice1 >>28)& 0x0000000FFFFFFF;
	key_right = key_after_choice1 & 0x0000000FFFFFFF;

	for(int round=0;round<16;round++)
	{
		key_left_after_rotate = leftRotate(key_left, numberOfShifts(round));
		key_right_after_rotate = leftRotate(key_right,numberOfShifts(round));
		//combine key again
		combine_key=((key_left_after_rotate<<28)&0XFFFFFFF0000000)|(key_right_after_rotate&0X0000000FFFFFFF);
		/*
		 * apply permuted choice 2 to key
		 */
		key_after_choice2=permute(combine_key,permutation_choice2,PC2,56);
		 /*
		  * save each round key in the keys array to use it in dicryption
		  * in decryption we inverse the keys array and use the same function
		  */
		key_array[round]=key_after_choice2;
		key_left=key_left_after_rotate;
		key_right=key_right_after_rotate;
	}
}
