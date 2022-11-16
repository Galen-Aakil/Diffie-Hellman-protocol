#include "DH.h"

int Diffie_Hellman_S(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey);
int Diffie_Hellman_C(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey);
int mychat(char *ser_addr,char *ser_addr2,int port,int port2,unsigned char* sharekey,unsigned char* sharekey2);//sc
int sig_ver_S(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex);

/*控制中间人程序流程*/
int main(int argc, char *argv[])
{
    	if (argc < 2)
    	{
        	printf("输入格式形如：  ./proc 127.0.0.1\n");
        	exit(-1);
    	}

	unsigned char pk1_hexc[KEYSIZE];//客户端DH公钥
	unsigned char pk2_hex[KEYSIZE];//中间人DH公钥
	unsigned char sharekeyc[KEYSIZE];//客户端与中间人共享密钥
	unsigned char pk1_hexcc[KEYSIZE];//服务器DH公钥
	unsigned char sharekeycc[KEYSIZE];//服务器与中间人共享密钥
	
	Diffie_Hellman_S(argv[1],10101,pk1_hexc,pk2_hex,sharekeyc);//与客户端Diffie_Hellman协商
	Diffie_Hellman_C(argv[1],10102,pk1_hexcc,pk2_hex,sharekeycc);//与服务器Diffie_Hellman协商
      //if(sig_ver_S(argv[1],10107,pk1_hexc,pk2_hex)==1)
        //{
		sleep(2);
		mychat(argv[1],argv[1],10103,10104,sharekeyc,sharekeycc);
	//}    
    
    return 0;
}

/*与客户端Diffie_Hellman协商*/
int Diffie_Hellman_C(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey)
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
    
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
    {
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

    for (i=0; i<32; i++)
    {
        chrtobit(sharekey[i]);
    }
	printf("\n");
	
	printf("--------------------------------------------------------------------------\n");
    	close(sockfd);
}

/*与服务器Diffie_Hellman协商*/
int Diffie_Hellman_S(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex,unsigned char *sharekey)
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
    
    if (bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Error ");
        exit(-1);
    }
    listen(server_sockfd, LISTEN_Q);
    
    if ((cli_sockfd = accept(server_sockfd, NULL, NULL)) < 0)
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
    
    /* 生成公私钥,服务器端 */
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
int sig_ver_S(char *ser_addr,int port,unsigned char *pk1_hex,unsigned char *pk2_hex)
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
	char private_key_path[] ="/home/robin/桌面/Intermediator_cscs/rsa_private_key_SC.pem";
	char public_key_path[] = "/home/robin/桌面/Intermediator_cscs/rsa_public_key_C.pem";
    	
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
int mychat(char *ser_addr,char *ser_addr2,int port,int port2,unsigned char* sharekey,unsigned char* sharekey2)
{
    int pid;
    int sockfd,client_fd;
    socklen_t len;
    struct sockaddr_in server_addr,client_addr;
    unsigned int lisnum = 5;//监听队列大小
    unsigned char plaintext[MAXBUF];//明文
    unsigned char key[32+1];//秘钥
    unsigned char key2[32+1];//秘钥
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
        key2[i]=sharekey2[i];
    }

    int sockfd2;
    struct sockaddr_in server_addr2;
    
    if((sockfd2=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
        perror("socket");
        exit(errno);
    }
    bzero(&server_addr2,sizeof(server_addr2));
    server_addr2.sin_family=AF_INET;
    server_addr2.sin_port=htons(port2);
    server_addr2.sin_addr.s_addr = inet_addr(ser_addr2);
	printf("请求连接\n");    
    if(connect(sockfd2,(struct sockaddr*)&server_addr2,sizeof(server_addr2))==-1)//发起连接请求
    {
        perror("connect");
        exit(errno);
    }
printf("连接成功\n");

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
    else if(pid==0)//接收客户端，发服务器
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
            len=recv(sockfd2,str,1024,0);
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
                printf("明文ciphertext=%s\n",ciphertext);
                k=strlen(ciphertext);
                printf("附加消息add=%s\n",aad);
                printf("密文长度k=%d\n",k);
                k = decrypt(ciphertext, k, aad, sizeof(aad), tag, key2, iv, pt);//AES256-GCM解密
                printf("收到的消息（密文解密后得到的明文）是：%s\n",pt);
                printf("－－－－－－－－－－－－－－－－－－－－－－－－\n");
                
                memset(plaintext, 0, MAXBUF);
                memset(ciphertext, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
                memset(tag, 0, 100);
                memset(iv, 0, 16);
                
                while(!RAND_bytes(iv,sizeof(iv)));
                
                printf("转发信息:");
                strcpy(plaintext,pt);
                printf("%s\n",plaintext);
                
                iv[17]='\0';
                k = encrypt(plaintext, strlen(plaintext), aad, sizeof(aad), key, iv, ciphertext, tag);
                
                memset(str, 0, 1024);
                strcat (str,"ciphertext=");
                strcat (str,ciphertext);
                strcat (str,"tag=");
                strcat (str,tag);
                strcat (str,"iv=");
                strcat (str,iv);
                printf("发送构造的报文为%s\n",str);
                len=send(client_fd,str,strlen(str),0);
                
                if(len<0)
                {
                    perror("send");
                    break;
                }
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
    else//接收服务器，发客户端
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
                printf("明文ciphertext=%s\n",ciphertext);
                k=strlen(ciphertext);
                printf("附加消息add=%s\n",aad);
                printf("密文长度k=%d\n",k);
                k = decrypt(ciphertext, k, aad, sizeof(aad), tag, key, iv, pt);//AES256-GCM解密
                printf("收到的消息（密文解密后得到的明文）是：%s\n",pt);
                printf("－－－－－－－－－－－－－－－－－－－－－－－－\n");

                memset(plaintext, 0, MAXBUF);
                memset(ciphertext, 0, MAXBUF+EVP_MAX_BLOCK_LENGTH);
                memset(tag, 0, 100);
                memset(iv, 0, 16);
                
                while(!RAND_bytes(iv,sizeof(iv)));
                
                printf("转发信息:");
                strcpy(plaintext,pt);
                printf("%s\n",plaintext);
                
                iv[17]='\0';
                k = encrypt(plaintext, strlen(plaintext), aad, sizeof(aad), key2, iv, ciphertext, tag);
                
                memset(str, 0, 1024);
                strcat (str,"ciphertext=");
                strcat (str,ciphertext);
                strcat (str,"tag=");
                strcat (str,tag);
                strcat (str,"iv=");
                strcat (str,iv);
                printf("发送构造的报文为%s\n",str);
                len=send(sockfd2,str,strlen(str),0);
                
                if(len<0)
                {
                    perror("send");
                    break;
                }
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
