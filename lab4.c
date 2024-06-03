

#include "common.h"

#define MTU 1000
#define PAYLOAD_SIZE (MTU - sizeof(ethernet_header_t) - sizeof(my_header_t))

#define WND_SIZE 100
#define BUFFER_SIZE 100
#define TIMEOUT 20
#define FINISH_TIMEOUT 2000



char role[10]; // sender or receiver, used for debug
unsigned char src_mac[6]="";
unsigned char dst_mac[6]="";



// the ring buffer to pass packets from the background thread to the foreground one
char buffer[BUFFER_SIZE][MTU];
int count;          // record the number of packet in the buffer
int head, tail;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;  // a shared buffer needs locks


// pcap handle for packet IO
pcap_t *handle = NULL;
char nic[10]="";
pthread_t bg_recv_t;


// helper function to get time stamp in millisecond
long long ts_0;
long long current_timestamp_millis(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)(tv.tv_sec)*1000 + (long long)(tv.tv_usec)/1000;
}



// put a packet in the buffer, we use a ring buffer
int put_packet(const u_char* packet, int size){
    /* printf("[%s] put_packet, size %d\n", role, size); fflush(stdout); */
    pthread_mutex_lock(&mutex);
    if(count == BUFFER_SIZE){
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    /* for(int i=0; i<28; i++) printf("%hhx ", packet[i]); printf("\n"); fflush(stdout); */
    memcpy(buffer[tail], packet, size);
    tail = (tail + 1) % BUFFER_SIZE;
    count++;
    pthread_mutex_unlock(&mutex);
    /* printf("[%s] put_packet, head %d, tail %d\n", role, head, tail); fflush(stdout); */
    return 0;
}


// read a packet from the ring buffer
int get_packet(char* pkt){
    /***********************************************
     * your code here
    ***********************************************/
    pthread_mutex_lock(&mutex);
    if(count == 0){
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    memcpy(pkt, buffer[head], MTU);
    head = (head + 1) % BUFFER_SIZE;
    count--;
    pthread_mutex_unlock(&mutex);
    return 1;
}




void recv_handler(u_char *user_data, const struct pcap_pkthdr *head, const u_char *pkt_data){
    /* printf("recv_handler\n"); fflush(stdout); */
    // get packet size
    ethernet_header_t *ether_header = (ethernet_header_t*)pkt_data;
    my_header_t *my_header = (my_header_t *)(pkt_data + sizeof(ethernet_header_t));
    int size = my_header->length;
    put_packet(pkt_data, size + sizeof(ethernet_header_t) + sizeof(my_header_t));
}

void* background_receiving(void* args){
    /* printf("[%s] background_receiving\n", role); fflush(stdout); */
    pcap_loop(handle, 0, recv_handler, NULL);
}


int init(char* smac, char* dmac, char* _nic, char* _role){
    memcpy(src_mac, smac, 6);
    memcpy(dst_mac, dmac, 6);
    memcpy(nic, _nic, strlen(_nic));
    memcpy(role, _role, strlen(_role));
    /* printf("[%s] init \n", role); fflush(stdout); */
    // init buffer
    head = tail = 0;
    count = 0;
    // pcap_recv
    char err_buf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live( nic, 65536, 10, 1, err_buf);
    if(handle==NULL){
        printf("cannot open device %s: %s \n", nic, err_buf); fflush(stdout);
        exit(1);
    }
    //***********************************************
     //* your code here
     //* start a background thread: capture packets from nic and put it into the ring buffer
    if (pthread_create(&bg_recv_t, NULL, background_receiving, NULL) != 0) {
        fprintf(stderr, "Error creating thread\n");
        exit(1);
    }
    
    //***********************************************/


    ts_0 = current_timestamp_millis();
    return 0;
}


int make_packet(char* packet, char* content, int size, unsigned char* src_mac, 
        unsigned char* dst_mac, int psn, int ack_flag){
    /* printf("[%s] make_packet: %d\n", role, psn); fflush(stdout); */
    ethernet_header_t *ether_header = (ethernet_header_t*)packet;
    my_header_t *my_header = (my_header_t*)(packet + sizeof(ethernet_header_t));
    char* payload = (char *)(packet + sizeof(ethernet_header_t) + sizeof(my_header_t));
    // ethernet header
    memcpy(ether_header->shost, src_mac, 6);
    memcpy(ether_header->dhost, dst_mac, 6);
    ether_header->type = 0xAAAA;
    // my header
    /***********************************************
     * your code here
     * fill in the new header "my_header"
    ***********************************************/
    my_header->seq_num = psn;
    my_header->length = size;
    my_header->ack_flag = ack_flag;

    // payload
    if (content!=NULL){
        memcpy(payload, content, size);
    }
    return 0;
}

/********************************************************************************
 * sender side 
********************************************************************************/

int una,next;

int send_pkt(const u_char *pkt, int len){
    //printf("=====================\n");
    //printf("Sent a packet\n");
   // printf("=====================\n");
    //fflush(stdout);
    //int ret = pcap_inject(handle, pkt, len);
    int ret = pcap_sendpacket(handle, pkt, len);
    if(ret==-1){
	    printf("Error Sending Packet: %s\n", pcap_geterr(handle)); fflush(stdout);
    }
}

int send_to_nic(char *addr, int size){
    una=next = 0;
    printf("send_to_nic\n"); fflush(stdout); 
    int num_pkt = (size + PAYLOAD_SIZE - 1) / PAYLOAD_SIZE;
    long long *ts = (long long *)malloc(1000 * sizeof(long long));
    int *acked = (int *)malloc(1000 * sizeof(int));
    memset(ts, 0, num_pkt*sizeof(int));
    memset(acked, 0, num_pkt*sizeof(int));

    /***********************************************
     * your code here
     * the sending side of the sliding window
    ***********************************************/
    char* getbuff = (char*)malloc(1000);
    while(1){
        if(get_packet(getbuff)){
            ethernet_header_t *ether_header = (ethernet_header_t*)getbuff;
            my_header_t *my_header = (my_header_t*)(getbuff + sizeof(ethernet_header_t));
            if(my_header->ack_flag == 1){
                //if(!acked[my_header->seq_num])printf("acked %d\n", my_header->seq_num); fflush(stdout);
                acked[my_header->seq_num] = 1;
            }
        }
        while(una < next && acked[una] == 1){
            una++;
        }
        if(una==num_pkt){
            break;
        }
        for(int i=una;i<una+WND_SIZE&&i<num_pkt&&i<next;i++){
            if(!acked[i]&&current_timestamp_millis()-ts[i]>TIMEOUT){
                char packet[MTU];
                int sz = i==num_pkt-1?size-i*PAYLOAD_SIZE:PAYLOAD_SIZE; 
                make_packet(packet, addr+i*PAYLOAD_SIZE, sz, src_mac, dst_mac, i, 0);
                send_pkt(packet, sz+sizeof(ethernet_header_t) + sizeof(my_header_t));
                ts[i] = current_timestamp_millis();
            }
        }
        for(int i=next;i<una+WND_SIZE&&i<num_pkt;i++){
            char packet[MTU];
            int sz = i==num_pkt-1?size-i*PAYLOAD_SIZE:PAYLOAD_SIZE; 
            make_packet(packet, addr+i*PAYLOAD_SIZE, sz, src_mac, dst_mac, i, 0);
            send_pkt(packet, sz+sizeof(ethernet_header_t) + sizeof(my_header_t));
            ts[i] = current_timestamp_millis();
        }
        next = una+WND_SIZE<num_pkt?una+WND_SIZE:num_pkt;
    }
    printf("send_to_nic done\n"); fflush(stdout);
    free(ts);
    free(acked);
    free(getbuff);
    pthread_cancel(bg_recv_t);
    return 0;
}

/********************************************************************************
 * receiver side 
********************************************************************************/

int recv_from_nic(char *addr, int size){
    printf("[%s] recv_from_nic\n", role); fflush(stdout); 
    int num_pkt = (size+PAYLOAD_SIZE-1)/PAYLOAD_SIZE;
    printf("num_pkt: %d\n", num_pkt); fflush(stdout);
    int *acked = (int*)malloc(10000 * sizeof(int));
    memset(acked, 0, num_pkt * sizeof(int));
    int ack_progress = 0;
    long long last_ack_ts = 0;
    /***********************************************
     * your code here
     * the sending side of the sliding window
    ***********************************************/
    char* getbuff = (char*)malloc(10000);
    while(1){
        if(get_packet(getbuff)){
            ethernet_header_t *ether_header = (ethernet_header_t*)getbuff;
            my_header_t *my_header = (my_header_t*)(getbuff + sizeof(ethernet_header_t));
            char* payload = (char*)(getbuff + sizeof(ethernet_header_t) + sizeof(my_header_t));
            acked[my_header->seq_num] = 1;
            memcpy(addr+my_header->seq_num*PAYLOAD_SIZE, payload, my_header->length);
            char packet[MTU];
            make_packet(packet, NULL, 0, src_mac, dst_mac, my_header->seq_num, 1);
            send_pkt(packet, sizeof(ethernet_header_t) + sizeof(my_header_t));
            last_ack_ts = current_timestamp_millis();
        }
        for(int i=0;i<num_pkt;i++){
            if(acked[i]==0){
                break;
            }
            if(i==num_pkt-1){
                ack_progress = 1;
            }
        }
        if(ack_progress==1&&current_timestamp_millis()-last_ack_ts>=1000){
            printf("%lld %lld\n",current_timestamp_millis(),last_ack_ts); fflush(stdout);
            printf("recv_from_nic done\n"); fflush(stdout);
            break;
        }
    }
    free(acked);
    free(getbuff);
    pthread_cancel(bg_recv_t);
    return 0;
}
