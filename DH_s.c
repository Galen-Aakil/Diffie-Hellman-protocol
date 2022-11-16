#include "DH.h"

int Diffie_Hellman(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey);
int mychat(char *ser_addr,int port,unsigned char*sharekey);
int sig_ver(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex);

/*控制服务器程序流程*/
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
	Diffie_Hellman(argv[1],10102,pk1_hex,pk2_hex,sharekey);//Diffie_Hellman协商
   
    	//if(sig_ver(argv[1],10102,pk1_hex,pk2_hex)==1)//RSA签名认证
    	//{
		sleep(1);
		mychat(argv[1],10104,sharekey);//通信
	//}    
    
    return 0;
}

/*Diffie_Hellman协商*/
int Diffie_Hellman(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey)
{
    printf("----------------------------------------------------------------\n");
    printf("SERVER\n");
    printf("----------------------------------------------------------------\n");
    printf("Server started! Waiting for connection from the client...\n\n");
    printf("-----------------------------Diffie-Hellman-------------------------------\n");     

    int server_sockfd, cli_sockfd;
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error ");
        exit(-1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(ser_addr);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)//绑定
    {
        perror("Error ");
        exit(-1);
    }
    listen(server_sockfd, LISTEN_Q);
    
    if ((cli_sockfd = accept(server_sockfd, NULL, NULL)) < 0)//连接
    {
        perror("Error ");
        exit(-1);
    }
    printf("Client connected!...\n\n");
    
    char buffer[MAX_LEN];
    memset(buffer, 0, sizeof(buffer));
    unsigned char p1_hex[KEYSIZE];
    unsigned char g1_hex[KEYSIZE];
     /*接收客户端发送的 key, generator and prime*/
    int recv_size = 64+1+64+1+2+1/*KEYSIZE * sizeof(char) * 3 + sizeof(char) * 3*/;
    int n = recv_message(cli_sockfd, buffer, recv_size);

     /*解析接收的数据*/
    printf("Peek :: %s",buffer);
    int ii = 0;
    int pa,pb,pc;
    while(buffer[ii]!='\n')
        ii++;
    pa = ii;
    ii++;
    while(buffer[ii]!='\n')
        ii++;
    pb = ii;
    ii++;
    while(buffer[ii]!='\n')
        ii++;
    pc = ii;
    printf("%d %d %d\n",pa, pb, pc);
    
    mystrcpy(pk1_hex,buffer,0,pa-1);
    mystrcpy(p1_hex,buffer,pa+1, pb-1);
    mystrcpy(g1_hex,buffer,pb+1,pc-1);
    
    printf("Client public key : %s\n", pk1_hex);
    printf("Global prime : %s\n", p1_hex);
    printf("Global primitive root : %s\n", g1_hex);
    
    BIGNUM* testbn;
    unsigned char nn[64];
    nn[0] = 0x2;
    testbn = BN_bin2bn(nn,64,NULL);
    char* after;
    BN_hex2bn(&testbn, p1_hex);
    after = BN_bn2hex(testbn);
    
    BN_hex2bn(&testbn, g1_hex);
    after = BN_bn2hex(testbn);
    
    DH *d2;
    d2=DH_new();
    d2->p = BN_bin2bn(nn,64,NULL);
    BN_hex2bn(&(d2->p), p1_hex);
    
    d2->g = BN_bin2bn(nn,64,NULL);
    BN_hex2bn(&(d2->g), g1_hex);
    BIO *b;
    int ret,size,i,len2;
    unsigned char prk2_hex[KEYSIZE];
    unsigned char p2_hex[KEYSIZE];
    unsigned char g2_hex[KEYSIZE];
     /*拷贝 p and g 到 d2(DH struct)*/
    BN_hex2bn(&testbn, p1_hex);
    BN_copy(d2->p,testbn);
    BN_hex2bn(&testbn, g1_hex);
    BN_copy(d2->g,testbn);
    ret =  BN_hex2bn(&testbn, pk1_hex);
    
     /*服务器生成公私钥*/
    ret=DH_generate_key(d2);
    if(ret!=1)
    {
        printf("DH_generate_key err!\n");
        return -1;
    }
    
    strcpy(pk2_hex, BN_bn2hex(d2->pub_key));
    strcpy(prk2_hex, BN_bn2hex(d2->priv_key));
    
    printf("Server private key : %s\n", prk2_hex);
    printf("Server public key : %s\n", pk2_hex);
    
     /*发送服务器的 public_key 给客户端*/
    memset(buffer, 0, sizeof(buffer));
    n = sprintf(buffer, "%s\n", pk2_hex);
    send_message(cli_sockfd, buffer, n);
    
     /*计算共享密钥*/
    len2=DH_compute_key(sharekey,testbn,d2);
    sharekey[33]='\0';
    printf("sharekey(256bits)\n");
        
        /*输出共享密钥*/    
	for (i=0; i<32; i++)
   	{
        chrtobit(sharekey[i]);
    	}
	printf("\n");

	printf("--------------------------------------------------------------------------\n");    
	close(server_sockfd);	
	close(cli_sockfd);
	return 0;
}

/*RSA签名认证*/
int sig_ver(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex)
{
	printf("--------------------------RSA签名认证HASH----------------------------------\n");
	int return_flag = 0;//签名结果
    	int sockfd,client_fd;
    	socklen_t len;
    	struct sockaddr_in server_addr,client_addr;
    	unsigned int lisnum = 5;
	char *buff_send;
	char *buff_recv;
	buff_send = malloc(520);
	buff_recv = malloc(520);
	char private_key_path[] ="/home/robin/桌面/Intermediator_cscs/rsa_private_key_S.pem";//RSA私钥路径
	char public_key_path[] = "/home/robin/桌面/Intermediator_cscs/rsa_public_key_C.pem";//RSA公钥路径
    	
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    	{
      	perror("socket");
		exit(EXIT_FAILURE);
    	}
    	bzero(&server_addr,sizeof(server_addr));
    	server_addr.sin_family=AF_INET;
    	server_addr.sin_port=htons(port);
    	server_addr.sin_addr.s_addr=inet_addr(ser_addr);
    	if(bind(sockfd,(struct sockaddr*)&server_addr,sizeof(struct sockaddr))==-1)//绑定
    	{
        	perror("bind");
        	exit(EXIT_FAILURE);
    	}
    	if(listen(sockfd,lisnum)==-1)//侦听
    	{
        	perror("listen");
        	exit(EXIT_FAILURE);
    	}

    	len=sizeof(struct sockaddr);
    	if((client_fd=accept(sockfd,(struct sockaddr*)&client_addr,&len))==-1)
    	{//堵塞等待连接
        	perror("accept");
      	exit(EXIT_FAILURE);
    	}
    	else
        printf("server:got connection from %s,port %d,socket %d\n",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port),client_fd);


	buff_send = Signature(pk1_hex,pk2_hex,private_key_path);//数字签名
	buff_send[256]='\0';
	len=send(client_fd,buff_send,256,0);//发送签名信息
	if(len<0)
        {
		perror("send");
        }
	len=recv(client_fd,buff_recv,520,0);//接收对端签名信息
	if (len<0)
        {
          perror("recv");
        }
	printf("收到客户端发送的签名认证信息，签名验证中...\n");
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
	close(client_fd);
    	close(sockfd);
	printf("--------------------------------------------------------------------------\n");
	return return_flag;
}

/*通信*/
int mychat(char *ser_addr,int port,unsigned char* sharekey)
{
    int pid;
    int sockfd,client_fd;
    socklen_t len;
    struct sockaddr_in server_addr,client_addr;
    unsigned int lisnum = 5;//监听队列大小
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
        exit(EXIT_FAILURE);
    }
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(port);
    server_addr.sin_addr.s_addr=inet_addr(ser_addr);
    if(bind(sockfd,(struct sockaddr*)&server_addr,sizeof(struct sockaddr))==-1)//绑定
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }
	printf("等待连接\n");
    if(listen(sockfd,lisnum)==-1)//侦听
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    len=sizeof(struct sockaddr);
    if((client_fd=accept(sockfd,(struct sockaddr*)&client_addr,&len))==-1)
    {//堵塞等待连接
        perror("accept");
        exit(EXIT_FAILURE);
    }
    else
    {
	printf("server:got connection from %s,port %d,socket %d\n",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port),client_fd);
	printf("享受安全的聊天吧...\n");  
    }	  
    
    if(-1==(pid=fork()))//创建新进程
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if(pid==0)
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
            len=send(client_fd,str,strlen(str),0);         
            if(len<0)
            	{
                perror("send");
                break;
            	}
        }
    }
    else
    {
        while(1)
        {
            memset(plaintext, 0, MAXBUF);
            memset(ciphertext, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(tag, 0, 100);
            memset(pt, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
            memset(iv, 0, 16);
            unsigned char str[1024];
            memset(str, 0, 1024);
            len=recv(client_fd,str,1024,0);
            if(len>0)
            {
                printf("－－－－－－－－－－－－－－－－－－－－－－－－\n");
                printf("收到构造的报文为%s\n",str);
                     /*报文内容解析*/
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
                printf("密文ciphertext=%s\n",ciphertext);
                k=strlen(ciphertext);
                printf("附加消息add=%s\n",aad);
                printf("密文长度k=%d\n",k);
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
    close(client_fd);
    close(sockfd);
    return 0;
}

