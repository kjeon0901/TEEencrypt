#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
char key_filename[20];
FILE *file;
int len=100;

void send_request_for_encryption(void){
	unsigned int encrypt_key;
	char ciphertext [100] = {0,};
	
	memcpy(op.params[0].tmpref.buffer, argv_filedata, len);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
	
	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("Ciphertext : %s", ciphertext);

	encrypt_key = op.params[1].value.a;
	//printf("root_key+random_key : %d, ", encrypt_key);

	char encrypted_filename[20] = "cipher_";
	strcat(encrypted_filename, argv_filename);
	FILE *e_file = fopen(encrypted_filename, "w");
	fputs(ciphertext, e_file);
	fclose(e_file);

	char char_key[20];
	sprintf(char_key, "%d\n", encrypt_key);

	char encrypted_key_filename[20] = "key_";
	strcat(encrypted_key_filename, argv_filename);
	FILE *k_file = fopen(encrypted_key_filename, "w");
	fputs(char_key, k_file);
	fclose(k_file);
}

void send_request_for_decryption(void){
	char char_key[20];
	char plaintext [100] = {0,};

	FILE *k_file =  fopen(key_filename, "r");
	fgets(char_key,  sizeof(char_key), k_file);
	fclose(k_file);
	op.params[1].value.a = atoi(char_key);

	memcpy(op.params[0].tmpref.buffer, argv_filedata, len);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);

	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("Plaintext : %s", plaintext);	
	//printf("decrypt_key : %d\n", op.params[1].value.a);

	char decrypted_filename[20] = "decrypted_";
	strcat(decrypted_filename, argv_filename);
	FILE *d_file = fopen(decrypted_filename, "w");
	fputs(plaintext, d_file);
	fclose(d_file);
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
		exit(1);
	}

	strcpy(argv_option, argv[1]);
	strcpy(argv_filename, argv[2]);

	if(strcmp(argv_option, "-d") == 0)
		strcpy(key_filename, argv[3]);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);	
	op.params[0].tmpref.buffer = argv_filedata;
	op.params[0].tmpref.size = len;

	file = fopen(argv_filename, "r");
	fgets(argv_filedata, sizeof(argv_filedata), file);
	fclose(file);

	if(strcmp(argv_option, "-e") == 0){
		printf(".....option for encryption.....\n");
		send_request_for_encryption(); 
	}
	else if(strcmp(argv_option, "-d") == 0){
		printf(".....option for decryption.....\n");
		send_request_for_decryption();
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

