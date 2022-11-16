#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <memory.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAXBUF 1024
#define M_ITERATION 15
#define MAX_LEN 1024
#define MAXSIZE 1000000
#define LISTEN_Q 5
#define KEYSIZE 128

/*发送信息*/
void send_message(int sockfd, char message[MAX_LEN], int len) 
{
	int n_sent = 0;
	while (n_sent < len) 
{
		int temp;
		if ((temp = send(sockfd, message + n_sent, len - n_sent, 0)) <= 0) 
		{
			perror("Error ");
			exit(-1);
		}
		n_sent += temp;
	}
}

/*接收信息*/
int recv_message(int sockfd, char buffer[MAX_LEN], int recv_size) 
{
	int n_recv = 0;
	while (n_recv < recv_size) 
	{
		int temp;
		if ((temp = recv(sockfd, buffer + n_recv, MAX_LEN - n_recv, 0)) <= 0) 
		{
			if (temp == 0)
				break;
			perror("Error ");
			exit(-1);
		}
		n_recv += temp;
	}
	return n_recv;
}

void handleErrors()
{
    printf("Some error occured\n");
}

/*AES256-GCM加密*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    
    int len=0, ciphertext_len=0;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();
    
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();
    
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    /* encrypt in block lengths of 16 bytes */
    while(ciphertext_len<=plaintext_len-16)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, 16))
            handleErrors();
        ciphertext_len+=len;
    }
    if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, plaintext_len-ciphertext_len))
        handleErrors();
    ciphertext_len+=len;
    
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) handleErrors();
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

/*AES256-GCM解密*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len=0, plaintext_len=0, ret;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();
    
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();
    
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    while(plaintext_len<=ciphertext_len-16)
    {
        if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, 16))
            handleErrors();
        plaintext_len+=len;
    }
    if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, ciphertext_len-plaintext_len))
        handleErrors();
    plaintext_len+=len;
    
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();
    
    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

/*拷贝数组*/
void mystrcpy(char* dest, const char* src, int startp, int endp)
{
    char * temp = dest;
    int i = 0;
    for(i = startp; i <=endp; i++)
    {
        *temp = src[i];
        temp++;
    }
    *temp = '\0';
}

/*以二进制形式输出的char值*/
void chrtobit(unsigned char chr)
{
    char tchr=chr;
    int i;
    for(i=7;i>=0;i--)
    {
        char tmpc=tchr;
        tmpc=tchr&(1<<i);
        printf("%d",tmpc>>i);
    }
}

/*输出hash值*/
void printHash(unsigned char *md, int len)
{
    
    int i = 0;
    for (i = 0; i < len; i++)
    {
        printf("%02x", md[i]);
    }
    
    printf("\n");
}


/*读取私钥*/
RSA* ReadPrivateKey(char* p_KeyPath)
{
    FILE *fp = NULL;
    char szKeyPath[1024];
    RSA  *priRsa = NULL, *pubRsa = NULL, *pOut = NULL;
    
    printf("PrivateKeyPath[%s] \n", p_KeyPath);
    
    /*	打开密钥文件 */
    if(NULL == (fp = fopen(p_KeyPath, "r")))
    {
        printf( "fopen[%s] failed \n", p_KeyPath);
        return NULL;
    }
    /*	获取私密钥 */
    priRsa = PEM_read_RSAPrivateKey(fp, NULL, NULL,NULL);
    if(NULL == priRsa)
    {
        ERR_print_errors_fp(stdout);
        printf( "PEM_read_RSAPrivateKey\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    
    pOut = priRsa;
    return pOut;
}

/*读取公匙*/
RSA* ReadPublicKey(char* p_KeyPath)
{
    FILE *fp = NULL;
    char szKeyPath[1024];
    RSA  *priRsa = NULL, *pubRsa = NULL, *pOut = NULL;
    
    printf("PublicKeyPath[%s]\n", p_KeyPath);
    
    /*	打开密钥文件 */
    if(NULL == (fp = fopen(p_KeyPath, "r")))
    {
        printf( "fopen[%s] \n", p_KeyPath);
        return NULL;
    }
    /*	获取私密钥 */
    if(NULL == (priRsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL,NULL)))
    {
        printf( "PEM_read_RSAPrivateKey error\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    
    pOut = priRsa;
    return pOut;
}

/*RSA数字签名*/
char* Signature(unsigned char *pk1_hex,unsigned char *pk2_hex,char *private_key_path)
{	
	//客户端公私key    	
    	unsigned char ct[256];
	memset(ct, 0, 256);
	strcat (ct,pk1_hex);
	strcat (ct,pk2_hex);
    	char *buf;
    	RSA *privKey;
    	int len;
    	int nOutLen;	
    	buf = malloc(520);
	
	memset(buf,0,520);	

    	//对数据进行sha512算法摘要
    	SHA512_CTX c;
    	unsigned char md[SHA512_DIGEST_LENGTH];
    
    	SHA512((unsigned char *)ct, strlen(ct), md);
    	
	printf("hash(客户端公钥|服务器公钥)：\n"); 
	printHash(md, SHA512_DIGEST_LENGTH);
    	privKey = ReadPrivateKey(private_key_path);
    	if (!privKey)
    	{
        	ERR_print_errors_fp (stderr);
        	exit (1);
    	}
    
    	/*签名:私钥加密*/
    	int nRet = RSA_sign(NID_sha512, md, SHA512_DIGEST_LENGTH, buf, &nOutLen, privKey);
    	if(nRet != 1)
    	{
        printf("RSA_sign err !!! \n");
        exit(1);
    	}
    	printf("RSA_sign:\n", nOutLen);
    	printHash(buf, nOutLen);

	md[64]='\0';
    
    	len = RSA_private_encrypt(SHA512_DIGEST_LENGTH, md, buf,privKey,RSA_PKCS1_PADDING);
    	if (len != 256)
     	{
     		printf("Error: ciphertext should match length of key len = %d \n", len);
     		exit(1);
     	}
	    
    	printf("RSA_private_encrypt:\n");
    	printHash(buf, strlen(buf));
	
	RSA_free(privKey);	
	return buf;
}

/*RSA签名验证*/
int Verification(char *buf_2,unsigned char *pk1_hex_2,unsigned char *pk2_hex_2,char *public_key_path)
{
    	RSA *pubKey;
    	int len=256;
	unsigned char *buf2;
    	buf2 = malloc(520);
	memset(buf2,0,520);

    	unsigned char ct_2[256];
	memset(ct_2, 0, 256);
	strcat (ct_2,pk1_hex_2);
	strcat (ct_2,pk2_hex_2);

	SHA512_CTX c_2;
    	unsigned char md_2[SHA512_DIGEST_LENGTH];
	memset(md_2,0,SHA512_DIGEST_LENGTH);
    	//gcc -o hi hi.c -lcrypto -lssl
    	SHA512((unsigned char *)ct_2, strlen(ct_2), md_2);
	printf("hash(客户端公钥|服务器公钥)：\n");     	
	printHash(md_2, SHA512_DIGEST_LENGTH);

    	pubKey = ReadPublicKey(public_key_path);
    	if(!pubKey)
	{
        	printf("Error: can't load public key");
        	exit(1);
    	}

    	/*公钥解密*/
    	RSA_public_decrypt(len, (const unsigned char*)buf_2, (unsigned char*)buf2,pubKey,RSA_PKCS1_PADDING);
    	printf("RSA_public_decrypt:\n");
    	printHash(buf2, strlen(buf2));

	int i=0;
	int equal = 1;
	for(i;i<64;)
	{
		if(buf2[i]==md_2[i])	
		{
			i++;
		}
		else 
		{
			equal=0;
			break;
		}	
	}
    	RSA_free(pubKey);
    	free(buf2);
	return equal;
}
