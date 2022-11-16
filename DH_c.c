#include "DH.h"

int Diffie_Hellman(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey);
int mychat(char *ser_addr,int port,unsigned char* sharekey);
int sig_ver(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex);

/*控制客户端程序流程*/
int main(int argc, char *argv[]) 
{
    	if (argc < 2) 
    	{
        printf("输入格式形如：  ./proc 127.0.0.1\n");
        exit(-1);
    	}

	unsigned char pk1_hex[KEYSIZE];
	unsigned char pk2_hex[KEYSIZE];
	unsigned char sharekey[KEYSIZE];
	Diffie_Hellman(argv[1],10101,pk1_hex,pk2_hex,sharekey);//Diffie_Hellman协商

	//sleep(1);
    	//if(sig_ver(argv[1],10107,pk1_hex,pk2_hex)==1)//RSA签名认证
    	//{
		//printf("正在连接服务器...\n");
		sleep(3);
		//printf("享受安全的聊天吧...\n"); 
		mychat(argv[1],10103,sharekey);//通信
	//}   
    return 0;

}

/*Diffie_Hellman协商*/
int Diffie_Hellman(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey)
{
    printf("---------------------------------------------------------------\n");
    printf("CLIENT\n");
    printf("---------------------------------------------------------------\n");
    printf("-----------------------------Diffie-Hellman-------------------------------\n");    
    DH *d1;
    BIO *b;
    int ret,size,i,len1;

    d1=DH_new();//构造DH数据结构
    
    ret=DH_generate_parameters_ex(d1,256,DH_GENERATOR_2,NULL);//生成d1的密钥参数
    if(ret!=1) 
    {
        printf("DH_generate_parameters_ex err!\n");
        return -1;
    }
    
     /*检查密钥参数*/
    ret=DH_check(d1,&i);//i先被置0,然后通过或等于,得到出错信息类型
    if(ret!=1) 
    {
        printf("DH_check err!\n");
        if(i&DH_CHECK_P_NOT_PRIME)
            printf("p value is not prime\n");
        if(i&DH_CHECK_P_NOT_SAFE_PRIME)
            printf("p value is not a safe prime\n");
        if (i&DH_UNABLE_TO_CHECK_GENERATOR)
            printf("unable to check the generator value\n");
        if (i&DH_NOT_SUITABLE_GENERATOR)
            printf("the g value is not a generator\n");
    }
    printf("DH parameters appear to be ok.\n");
    
     /*生成公私钥*/
    ret=DH_generate_key(d1);
    
    unsigned char prk1_hex[KEYSIZE];
    unsigned char p1_hex[KEYSIZE];
    unsigned char g1_hex[KEYSIZE];
    
     /*将大数转换成字符数组*/
    strcpy(pk1_hex, BN_bn2hex(d1->pub_key));
    printf("client pub_key in HEX: %s\n",pk1_hex);
    strcpy(prk1_hex, BN_bn2hex(d1->priv_key));
    printf("client priv_key in HEX: %s\n",prk1_hex);
    strcpy(p1_hex, BN_bn2hex(d1->p));
    printf("client p in HEX: %s\n",p1_hex);
    strcpy(g1_hex, BN_bn2hex(d1->g));
    printf("client g in HEX: %s\n",g1_hex);

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Error ");
        exit(-1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ser_addr);
    serv_addr.sin_port = htons(port);
    
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error ");
        exit(-1);
    }
    
     /*发送 public_key, generator and prime 给服务器*/
    char message[MAX_LEN];
    memset(message, 0, sizeof(message));
    int n = sprintf(message, "%s\n%s\n%s\n", pk1_hex, p1_hex, g1_hex);//pk p g
    
    send_message(sockfd, message, n);
    memset(message, 0, sizeof(message));

     /*收到服务器发来的 public key*/
    n = recv_message(sockfd, message, KEYSIZE * sizeof(char) + sizeof(char));
    
    mystrcpy(pk2_hex, message, 0, 63);
    printf("Server public key : %s\n",pk2_hex);

     /*计算共享密钥*/
    DH* dTemp;
    dTemp = DH_new();
    ret =  BN_hex2bn(&(dTemp->p), pk2_hex); //Needed later for final-keygeneration /printf("DH_check err!\n");
    len1=DH_compute_key(sharekey,dTemp->p,d1);
    sharekey[33]='\0';
    printf("sharekey(256bits)\n");

     /*输出共享密钥*/
    for (i=0; i<32; i++)
    {
        chrtobit(sharekey[i]);
    }
	printf("\n");
	
	printf("--------------------------------------------------------------------------\n");
    	close(sockfd);
}

/*RSA签名认证*/
int sig_ver(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex)
{
	printf("--------------------------RSA签名认证HASH----------------------------------\n");
	int return_flag = 0;//签名结果
    	int sockfd,len;
    	struct sockaddr_in server_addr;
    	char *buff_send;
    	char *buff_recv;
    	buff_send = malloc(520);
    	buff_recv = malloc(520);
    	char private_key_path[] ="/home/robin/桌面/Intermediator_cscs/rsa_private_key_C.pem";//RSA私钥路径
    	char public_key_path[] = "/home/robin/桌面/Intermediator_cscs/rsa_public_key_S.pem";//RSA公钥路径
    
    	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    	{
        	perror("socket");
        	exit(errno);
   	}
    	bzero(&server_addr,sizeof(server_addr));
    	server_addr.sin_family=AF_INET;
    	server_addr.sin_port=htons(port);
    	server_addr.sin_addr.s_addr = inet_addr(ser_addr);
    
    	if(connect(sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr))==-1)//发起连接请求
    	{
        	perror("connect");
        	exit(errno);
    	}

	buff_send = Signature(pk1_hex,pk2_hex,private_key_path);//数字签名
	buff_send[256]='\0';            
	len=send(sockfd,buff_send,256,0);//发送签名信息
      if(len<0)
	{
		perror("send");
	}
	len=recv(sockfd,buff_recv,520,0);//接收对端签名信息
	if (len<0)
        {
		perror("recv");
        }
	printf("收到服务器发送的签名认证信息，签名验证中...\n");
	if(Verification(buff_recv,pk1_hex,pk2_hex,public_key_path)==1)//签名认证
        {
		printf("签名认证通过\n");
		return_flag = 1;
	}
      else
        {
            printf("签名认证失败\n");
        }
        
	free(buff_send);
	free(buff_recv);
	close(sockfd);
	printf("--------------------------------------------------------------------------\n");
	return return_flag;
}

/*通信*/
int mychat(char *ser_addr,int port,unsigned char* sharekey)
{
    int sockfd,len;
    struct sockaddr_in server_addr;
    unsigned char plaintext[MAXBUF];//明文
    unsigned char key[32+1];//秘钥
    unsigned char ciphertext[MAXBUF+EVP_MAX_BLOCK_LENGTH];//密文
    unsigned char tag[100];//消息验证码
    unsigned char pt[MAXBUF+EVP_MAX_BLOCK_LENGTH];//密文解密后得到的明文
    unsigned char iv[16+1];//计数器的初始值
    unsigned char aad[16+1]="abcdefghijklmnop";//附加消息
    int k;
    
    int i=0;
    for(i=0;i<33;i++)
    {
        key[i]=sharekey[i];
    }
    
    if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
        perror("socket");
        exit(errno);
    }
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ser_addr);
    
    if(connect(sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr))==-1)//发起连接请求
    {
        perror("connect");
        exit(errno);
    }
    pid_t pid;
    
    if(-1==(pid=fork()))//创建新进程
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if(pid==0)//子进程用于数据接收
    {
        while(1)
        {
		/*报文内容解析*/
            memset(plaintext, 0, MAXBUF);
            memset(ciphertext, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(tag, 0, 100);
            memset(pt, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(iv, 0, 16);
            unsigned char str[1024];
            memset(str, 0, 1024);
            len=recv(sockfd,str,1024,0);
            if(len>0)
            {
                printf("－－－－－－－－－－－－－－－－－－－－－－－－\n");
                printf("收到构造的报文为%s\n",str);
                printf("－－－－－－本地报文解密－－－－－－\n");
                unsigned char *p1,*p2,*p3;
                p1=strstr(str,"iv=");
                int pos3 = strlen(str)- strlen(p1)+3;
                p2=strstr(str,"tag=");
                int pos2 = strlen(str)- strlen(p2)+4;
                memset(tag, 0, 100);
                memset(ciphertext, 0, 1024+EVP_MAX_BLOCK_LENGTH);
                memset(iv, 0, 16);
                int i=0;
                for(i = 0;i<16;i++)
                {
                    iv[i]=str[pos3+i];
                }
                iv[i]='\0';
                printf("计数器的初始值iv=%s\n",iv);
                for(i=0;i<pos3-pos2-3;i++)
                {
                    tag[i]=str[pos2+i];
                }
                tag[i]='\0';
                printf("消息验证码tag=%s\n",tag);
                for(i=0;i<pos2-4-11;i++)
                {
                    ciphertext[i]=str[11+i];
                }
                ciphertext[i]=='\0';
                printf("明文ciphertext=%s\n",ciphertext);
                k=strlen(ciphertext);
                printf("附加消息add=%s\n",aad);
                printf("密文长度k=%d\n",k);
                printf("密钥key=%s\n",key);
                k = decrypt(ciphertext, k, aad, sizeof(aad), tag, key, iv, pt);//AES256-GCM解密
                printf("收到的消息（密文解密后得到的明文）是：%s\n",pt);
                printf("－－－－－－－－－－－－－－－－－－－－－－－－\n输入信息（回车发送）:");
            }
            else if (len<0)
            {
                printf("recv failure!errno code is %d,errno message is '%s'\n",errno,strerror(errno));
                break;
            }
            else
            {
                printf(" the other one close,quit\n");
                break;
            }
        }
    }
    else//父进程用于数据发送
    {
        while(1)
        {
            memset(plaintext, 0, MAXBUF);
            memset(ciphertext, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(tag, 0, 100);
            memset(pt, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(iv, 0, 16);
            
            while(!RAND_bytes(iv,sizeof(iv)));
	      printf("－－－－－－－－－－－－－－－－－－－－－－－－\n");            
            printf("输入信息（回车发送）:\n");
            scanf("%s",plaintext);
            
            iv[17]='\0';
            k = encrypt(plaintext, strlen(plaintext), aad, sizeof(aad), key, iv, ciphertext, tag);//AES256-GCM加密
            	
		/*报文内容构造*/
            unsigned char str[1024];
            memset(str, 0, 1024);
            strcat (str,"ciphertext=");
            strcat (str,ciphertext);
            strcat (str,"tag=");
            strcat (str,tag);
            strcat (str,"iv=");
            strcat (str,iv);
            printf("发送构造的报文为：%s\n",str);
            len=send(sockfd,str,strlen(str),0);
            if(len<0)
            	{
                perror("send");
                break;
            	}
        }
    }
    close(sockfd);
    return 0;
}

