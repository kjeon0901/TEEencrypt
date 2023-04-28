#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

TEEC_Result res;
TEEC_Context ctx;
TEEC_Session sess;
TEEC_Operation op;
TEEC_UUID uuid = TA_TEEencrypt_UUID;
uint32_t err_origin;

char argv_option[10];
char argv_filename[100];
char argv_filedata[100];
FILE *file;
int len=100;

void send_request_for_encryption(void){
	unsigned int encrypt_key;
	char ciphertext [100] = {0,};
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
	if (res!=TEEC_SUCCESS) 
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("Ciphertext : %s\n", ciphertext);

	//encrypt_key = op.params[1].value.a;
	encrypt_key = 3;
	printf("Encrypt_Key : %d\n", encrypt_key);

	char encrypted_filename[20] = "e_";
	strcat(encrypted_filename, argv_filename);
	FILE *e_file = fopen(encrypted_filename, "w");
	fputs(ciphertext, e_file);
	fclose(e_file);
}

void send_request_for_decryption(void){
	char plaintext [100] = {0,};
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("Plaintext : %s\n", plaintext);
}

int main(int argc, char *argv[])
{
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	if(argc < 3){
		printf("Not enough parameter. \n");
		return 0;
	}

	strcpy(argv_option, argv[1]);
	strcpy(argv_filename, argv[2]);

	if(strcmp(argv_option, "-d") == 0)
		strcpy(argv_filename, argv[3]);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);	
	op.params[0].tmpref.buffer = argv_filedata;
	op.params[0].tmpref.size = len;

	file = fopen(argv_filename, "r");
	fgets(argv_filedata, sizeof(argv_filedata), file);
	fclose(file);

	memcpy(op.params[0].tmpref.buffer, argv_filedata, len);

	if(strcmp(argv_option, "-e") == 0){
		printf(".....option for encryption.....");
		send_request_for_encryption(); // CA -> TA send request for encryption
	}
	else if(strcmp(argv_option, "-d") == 0){
		printf(".....option for decryption.....");
		send_request_for_decryption(); // CA -> TA send request to decryption
	}

	
	
	/*
	
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
	*/


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

