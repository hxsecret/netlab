
#define RECV_SIZE 256
#define SEND_SIZE 102400 

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

const int buffer_size = 102400;

// helpers
int to_base64(char* dst, char* src, int size);
int uuencode(char* file_name, char* dst_buff);
int prepare_DATA(char* from_email, char* to_email, char* subject, char* body, char* attach_file, char* target_DATA);


// connection 

/**********************************************************************
 * the socket descriptor is stored in cfd
**********************************************************************/
int cfd;
int establish_connection();
int close_connection();

// email sending
int request_and_response(char* request, char* response);
int send_email(char* account, char* password, char* from_email, char* to_email, 
        char* subject, char* body, char* attachment_path);




int to_base64(char* dst, char* src, int size){
    char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int str_len=strlen(src);  
    int len = 0;
    int i, j;
    
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
    dst[len]='\0'; 
  
    //以3个8位字符为一组进行编码  
    for(i=0, j=0;i<len-2;j+=3,i+=4)
    {  
        //取出第一个字符的前6位并找出对应的结果字符 
        dst[i]=base64_table[src[j]>>2];  
        //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        dst[i+1]=base64_table[(src[j]&0x3)<<4 | (src[j+1]>>4)]; 
        //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        dst[i+2]=base64_table[(src[j+1]&0xf)<<2 | (src[j+2]>>6)]; 
        //取出第三个字符的后6位并找出结果字符 
        dst[i+3]=base64_table[src[j+2]&0x3f];  
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            dst[i-2]='=';  
            dst[i-1]='=';  
            break;  
        case 2:  
            dst[i-1]='=';  
            break;  
    }
    printf("%s to %s\n",src, dst);
    return 0;
}


int uuencode(char* file_name, char* dst_buff){
    char cmd[50]="";
    sprintf(cmd, "uuencode %s %s > temp", file_name, file_name);
    system(cmd);
    FILE *fd = fopen("temp", "r");
    char buff[200];
    strcpy(dst_buff, "");
    // first line: three strings
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, " ");
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, " ");
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, "\n");
    // remaining lines 
    while(fscanf(fd, "%s", buff)!=EOF){
        //printf("%s", buff);
        strcat(dst_buff, buff);
        strcat(dst_buff, "\n");
        //printf("%s", dst_buff);
    }
    system("rm temp");
}

int establish_connection(){
    // build TCP connection to PKU SMTP server
    // address (name): smtphz.qiye.163.com
    // port: 25
    // put the socker descriptor in the global variable cfd
    // find a way to translate the domain name to IP address, so you can establish the connection
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
    cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cfd < 0) {
        perror("socket failed");
        return -1;
    }
    
    struct sockaddr_in saddr;
    char *host = "smtphz.qiye.163.com";
    struct addrinfo hints, *res;
    int ret;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    ret = getaddrinfo(host, "25", &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }
    
    memcpy(&saddr, res->ai_addr, res->ai_addrlen);
    
    
    if (connect(cfd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
        perror("connect() failed");
        freeaddrinfo(res); 
        return -1;
    }
    
    freeaddrinfo(res); 
    
    return cfd;
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/
}

int close_connection(){
    close(cfd);
}

int request_and_response(char* request, char* response){
    // send a request and recv a response by socket
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
    int nbytes; 

    if (request == NULL) {
        fprintf(stderr, "Request is NULL\n");
        return -1;
    }
    if (send(cfd, request, strlen(request), 0) == -1) {
        perror("send");
        return -1;
    }

    char buffer[buffer_size];
    nbytes = recv(cfd, buffer, buffer_size - 1, 0);
    printf("From server: %s\n", buffer);
    if (nbytes == -1) {
        perror("recv");
        return -1;
    }
    else if (nbytes == 0) {
        fprintf(stderr, "Connection closed by the server\n");
        return -1;
    }

    buffer[nbytes] = '\0';
    if (response != NULL) {
        strcpy(response, buffer);
    }

    return 0;
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/
}


int prepare_DATA(char* from_email, char* to_email, char* subject, char* body, char* attach_file, char* target_DATA){
    char temp[102400]; // 100KB
    strcpy(target_DATA, "");
        // FROM
    sprintf(temp, "From: %s@stu.pku.edu.cn\r\n", from_email);
    strcat(target_DATA, temp);

    // build other fields: TO, SUBJECT, BODY, ATTACHMENT
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
        //TO
    sprintf(temp, "To: %s\r\n", to_email);
    strcat(target_DATA, temp);

        //SUBJECT
    sprintf(temp, "Subject: %s\r\n\r\n", subject);
    strcat(target_DATA, temp);
        //BODY
    sprintf(temp, "%s\r\n", body);
    strcat(target_DATA, temp);
    
        //ATTACHMENT
    if (attach_file != NULL) {
        char *encoded_content = malloc(1024 * 1024 * 100);
        if (uuencode(attach_file, encoded_content) != 0) {
            free(encoded_content);
            return -1;
        }
        sprintf(temp, "%s\r\n\r\n", encoded_content);
        strcat(target_DATA, temp);
        
    } 
    else strcat(target_DATA, "\r\n");
    

    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/
    strcat(target_DATA, ".\r\n");
}





int send_email(char* username, char* password, char* from_email, char* to_email, 
        char* subject, char* body, char* attachment_path){

    establish_connection();
    
    char temp[100];
    char rbuf[RECV_SIZE];
    char sbuf[SEND_SIZE];    
    char encoded_username[SEND_SIZE];
    char encoded_password[SEND_SIZE];
    char target_DATA[102400];

    // recv from server
    recv(cfd, rbuf, RECV_SIZE, 0);
    printf("From server: %s\n", rbuf);

    // send HELO
    sprintf(sbuf, "HELO smtp\r\n");
    request_and_response(sbuf, rbuf);
    // send other requests, fill in the reqeust_and_response() function and use it here
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/

	// send AUTH 
    sprintf(sbuf, "AUTH LOGIN\r\n");
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send username (base64)
    to_base64(encoded_username, from_email, sizeof(encoded_username));
    to_base64(encoded_password, password, sizeof(encoded_password));
    sprintf(sbuf, "%s\r\n", encoded_username);
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send password (base64)
    sprintf(sbuf, "%s\r\n", encoded_password);
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send MAIL FROM
    printf("%s\n",from_email);
    
    sprintf(sbuf, "MAIL FROM:<%s>\r\n", from_email);
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send RCPT TO
    sprintf(sbuf, "RCPT TO:<%s>\r\n", to_email);
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send DATA
    sprintf(sbuf, "DATA\r\n");
    if (request_and_response(sbuf, rbuf) < 0) {
        close_connection();
        return -1;
    }
	// send email (this step is complex, do it in prepare_DATA()
    if (prepare_DATA(username, to_email, subject, body, attachment_path, target_DATA) < 0) {
        close_connection();
        printf("prepare_DATA failed\n");
        return -1;
    }
    if (request_and_response(target_DATA, rbuf) < 0) {
        close_connection();
        printf("request_and_response failed\n");
        return -1;
    }
	// send QUIT
    sprintf(sbuf, "QUIT\r\n");
    if (request_and_response(sbuf, rbuf) < 0) {
        return -1;
    }
    close_connection();

    return 0;
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/



    
    // CLOSE TCP
   
    close_connection();

    return 0;
}
