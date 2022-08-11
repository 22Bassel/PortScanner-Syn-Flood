#include<stdio.h> //printf
#include<stdbool.h> //boolean
#include<string.h> //memset

#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h>	//hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
 
#include <gtk/gtk.h>




GtkWidget *mainlabel0;
GtkWidget *mainlabel1;
GtkWidget *mainlabel2;
GtkWidget *mainlabel3;
GtkWidget *mainlabel4;
GtkWidget *mainlabel5;
GtkWidget *mainlabel6;
GtkWidget *mainlabel7;
GtkWidget *mainlabel8;
GtkWidget *mainlabel9;
GtkWidget *mainlabel10;
GtkWidget *mainlabel11;
GtkWidget *mainlabel12;
GtkWidget *mainlabel13;
GtkWidget *mainlabel14;





void * listen_to_receive_ack( void *ptr );
void check_packet(unsigned char* , int);
unsigned short check_sum(unsigned short * , int );
//char * hostname_to_ip(char * );
int get_local_ip (char *);



struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};


struct in_addr dest_ip;

/*
	Method to sniff incoming packets and look for Ack replies
*/
void * listen_to_receive_ack( void *ptr )
{
	//Start the sniffer thing
	start_sniffer();
}


int val=0;

int start_sniffer()
{
	int sock_raw;
	
	int saddr_size , data_size;
	struct sockaddr saddr;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	printf("Sniffer initialising...\n");

	fflush(stdout);
	

	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	
		
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}
		
	
	saddr_size = sizeof saddr;
		
		
	gtk_label_set_text(GTK_LABEL(mainlabel0),"");
	gtk_label_set_text(GTK_LABEL(mainlabel1),"");
	gtk_label_set_text(GTK_LABEL(mainlabel2),"");
	gtk_label_set_text(GTK_LABEL(mainlabel3),"");
	gtk_label_set_text(GTK_LABEL(mainlabel4),"");
	gtk_label_set_text(GTK_LABEL(mainlabel5),"");
	gtk_label_set_text(GTK_LABEL(mainlabel6),"");
	gtk_label_set_text(GTK_LABEL(mainlabel7),"");
	gtk_label_set_text(GTK_LABEL(mainlabel8),"");
	gtk_label_set_text(GTK_LABEL(mainlabel9),"");
	gtk_label_set_text(GTK_LABEL(mainlabel10),"");
	gtk_label_set_text(GTK_LABEL(mainlabel11),"");
	gtk_label_set_text(GTK_LABEL(mainlabel12),"");
	gtk_label_set_text(GTK_LABEL(mainlabel13),"");
	gtk_label_set_text(GTK_LABEL(mainlabel14),"");

	val=0;
		
	while(1)
	{
	
	
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		
	
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}
		
		//Now process the packet
		check_packet(buffer , data_size);
	}
	
	close(sock_raw);
	printf("Sniffer finished.");
	fflush(stdout);
	return 0;
}

void check_packet(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
	
	
	//printf("a new packet !! ");
		
	if(iph->protocol == 6)
	{
	
	
	//
		struct iphdr *iph = (struct iphdr *)buffer;
		iphdrlen = iph->ihl*4;
		
		
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
			
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;
	
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;
		
		
		if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr )
		{
	
	char buffer[1024];
	snprintf(buffer,1024,"port %d open",ntohs(tcph->source));
	gchar *entry0_text=buffer;
	
//gtk_label_set_text(GTK_LABEL(mainlabel0),entry0_text);	
	
		if(val==0){  		 gtk_label_set_text(GTK_LABEL(mainlabel0),entry0_text);
val++;}
		else if(val==1){  		 gtk_label_set_text(GTK_LABEL(mainlabel1),entry0_text);
val++;
}
else if(val==2){  		 gtk_label_set_text(GTK_LABEL(mainlabel2),entry0_text);
val++;
}
else if(val==3){  		 gtk_label_set_text(GTK_LABEL(mainlabel3),entry0_text);
val++;
}
else if(val==4){  		 gtk_label_set_text(GTK_LABEL(mainlabel4),entry0_text);
val++;
}
else if(val==5){  		 gtk_label_set_text(GTK_LABEL(mainlabel5),entry0_text);
val++;
}
else if(val==6){  		 gtk_label_set_text(GTK_LABEL(mainlabel6),entry0_text);
val++;
}
else if(val==7){  		 gtk_label_set_text(GTK_LABEL(mainlabel7),entry0_text);
val++;
}
else if(val==8){  		 gtk_label_set_text(GTK_LABEL(mainlabel8),entry0_text);
val++;
}
else if(val==9){  		 gtk_label_set_text(GTK_LABEL(mainlabel9),entry0_text);
val++;
}

else if(val==10){  		 gtk_label_set_text(GTK_LABEL(mainlabel10),entry0_text);
val++;
}
else if(val==11){  		 gtk_label_set_text(GTK_LABEL(mainlabel11),entry0_text);
val++;
}
else if(val==12){  		 gtk_label_set_text(GTK_LABEL(mainlabel12),entry0_text);
val++;
}
else if(val==13){  		 gtk_label_set_text(GTK_LABEL(mainlabel13),entry0_text);
val++;
}
else if(val==14){  		 gtk_label_set_text(GTK_LABEL(mainlabel14),entry0_text);
val++;
}

			printf("Port %d open \n" , ntohs(tcph->source));
			fflush(stdout);
		}
		
		
	}
}

/*
 Checksums - IP and TCP
 */
unsigned short check_sum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	//printf("n= %d * ",nbytes);
	while(nbytes>1) {
		sum+=*ptr++;
		//printf("- %d -",sum);
		nbytes-=2;
	}
	
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

        //printf("sum1= %d ",sum);
	sum = (sum>>16)+(sum & 0xffff);
	//printf("sum2= %d ",sum);
	sum = sum + (sum>>16);
	//printf("sum3= %d ",sum);
	
	answer=(short)~sum;
	
	return(answer);
}


/*
 Get source IP of system , like 192.168.0.6 or 192.168.1.2
 */

int get_local_ip ( char * buffer)
{
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
}























////////////////////////////////////
//gui
///////////////////////////////////

GtkWidget *entry0;
GtkWidget *entry1;
GtkWidget *entry2;

const gchar *entry0_text;
const gchar *entry1_text;
const gchar *entry2_text;
const gchar *mainlabel_text;


static void my_function1 (void)
{
  entry0_text = gtk_entry_get_text (GTK_ENTRY (entry0));
  entry1_text = gtk_entry_get_text (GTK_ENTRY (entry1));
  entry2_text = gtk_entry_get_text (GTK_ENTRY (entry2));


  

	int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
	
	
	if(s < 0)
	{
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	else
	{
		printf("Socket created.\n");

	}
	
	//Datagram to represent the packet
	char datagram[4096];	
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	
	struct sockaddr_in  dest;
	struct pseudo_header psh;
	
	char *target = entry0_text;
	char *port= entry1_text;

	


	
	dest_ip.s_addr = inet_addr( target );
	
	
	int source_port = 43591;
	char source_ip[20];

	get_local_ip( source_ip );
	
	printf("Local source IP is %s \n" , source_ip);
	
	memset (datagram, 0, 4096);
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (54321);	//Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = dest_ip.s_addr;
	
	iph->check = check_sum ((unsigned short *) datagram, iph->tot_len >> 1);
	
	//TCP Header
	tcph->source = htons ( source_port );
	tcph->dest = htons (80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	
	tcph->window = htons ( 14600 );	// maximum allowed window size
	tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcph->urg_ptr = 0;
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	printf("Starting sniffer thread...\n");
	char *message1 = "Thread 1";
	int  iret1;
	
	pthread_t sniffer_thread;

	if( pthread_create( &sniffer_thread , NULL ,  listen_to_receive_ack , (void*) message1) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	sleep(1);
	printf("Starting to send syn packets\n");
	int p;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	

		p=atoi(port);

		tcph->dest = htons ( p );
		tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
		
		//pseudo_header psh;
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons( sizeof(struct tcphdr) );
		
		memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
		
		tcph->check = check_sum( (unsigned short*) &psh , sizeof (struct pseudo_header));
		
		//Send the packet
		if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
		{
			printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
			exit(0);
		}
	
	
	

	sleep(5);


	printf("%d" , iret1);
	

	

}





/////////////////////
static void my_function2 (void)
{
  entry0_text = gtk_entry_get_text (GTK_ENTRY (entry0));
  entry1_text = gtk_entry_get_text (GTK_ENTRY (entry1));
  entry2_text = gtk_entry_get_text (GTK_ENTRY (entry2));




	int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
	
	
	if(s < 0)
	{
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	else
	{
		printf("Socket created.\n");

	}
	
	//Datagram to represent the packet
	char datagram[4096];	
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	
	struct sockaddr_in  dest;
	struct pseudo_header psh;
	
	char *target = entry0_text;
	char *port= entry1_text;
	char *endport= entry2_text;

	


	
	dest_ip.s_addr = inet_addr( target );
	
	
	int source_port = 43591;
	char source_ip[20];

	get_local_ip( source_ip );
	
	printf("Local source IP is %s \n" , source_ip);
	
	memset (datagram, 0, 4096);
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (54321);	//Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = dest_ip.s_addr;
	
	iph->check = check_sum ((unsigned short *) datagram, iph->tot_len >> 1);
	
	//TCP Header
	tcph->source = htons ( source_port );
	tcph->dest = htons (80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons ( 14600 );	// maximum allowed window size
	tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcph->urg_ptr = 0;
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	printf("Starting sniffer thread...\n");
	char *message1 = "Thread 1";
	int  iret1;
	
	pthread_t sniffer_thread;

	if( pthread_create( &sniffer_thread , NULL ,  listen_to_receive_ack , (void*) message1) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	sleep(1);
	printf("Starting to send syn packets\n");
	int p;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	
	
	for(p = atoi(port) ; p <= atoi(endport) ; p++)
	{
	
		tcph->dest = htons ( p );
		tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
		
		//pseudo_header psh;
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons( sizeof(struct tcphdr) );
		
		memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
		
		tcph->check = check_sum( (unsigned short*) &psh , sizeof (struct pseudo_header));
		
		//Send the packet
		if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
		{
			printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
			exit(0);
		}
	}

		sleep(5);

	printf("%d" , iret1);
	

}


static void
activate (GtkApplication *app,
          gpointer        user_data)
{
  GtkWidget *window;
  GtkWidget *grid;
  GtkWidget *button;
  GtkWidget *button2;

  GtkWidget *label;
  GtkWidget *label2;
  GtkWidget *label3;
  
  GtkWidget *label_=gtk_label_new("---------------");
  
  
  mainlabel0=gtk_label_new("");
  mainlabel1=gtk_label_new("");
  mainlabel2=gtk_label_new("");
  mainlabel3=gtk_label_new("");
  mainlabel4=gtk_label_new("");
  mainlabel5=gtk_label_new("");
  mainlabel6=gtk_label_new("");
  mainlabel7=gtk_label_new("");
  mainlabel8=gtk_label_new("");
  mainlabel9=gtk_label_new("");
  mainlabel10=gtk_label_new("");
  mainlabel11=gtk_label_new("");
  mainlabel12=gtk_label_new("");
  mainlabel13=gtk_label_new("");
  mainlabel14=gtk_label_new("");
  
  window = gtk_application_window_new (app);
  gtk_window_set_title (GTK_WINDOW (window), "Port Scanner");
  gtk_window_set_default_size (GTK_WINDOW (window), 400, 400);
  gtk_container_set_border_width (GTK_CONTAINER (window), 30);

  grid = gtk_grid_new ();
  gtk_container_add (GTK_CONTAINER (window), GTK_WIDGET (grid));

  label = gtk_label_new("IP : ");
  gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
    
  entry0 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry0, 1, 0, 1, 1);


  label2 = gtk_label_new("start port : ");
  gtk_grid_attach(GTK_GRID(grid), label2, 0, 1, 1, 1);
    
  entry1 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry1, 1, 1, 1, 1);


  label3 = gtk_label_new("end port : ");
  gtk_grid_attach(GTK_GRID(grid), label3, 0, 2, 1, 1);
    
  entry2 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry2, 1, 2, 1, 1);


  //label4 = gtk_label_new("scan one port");
  
  button = gtk_button_new_with_label("scan one port");
  //button.set_label(label4);
  gtk_grid_attach (GTK_GRID (grid), button, 1, 3, 1, 1);
  g_signal_connect (button, "clicked", G_CALLBACK (my_function1), NULL);

  button2 = gtk_button_new_with_label ("scan a range of ports");
  gtk_grid_attach (GTK_GRID (grid), button2, 1, 4, 1, 1);
  g_signal_connect (button2, "clicked", G_CALLBACK (my_function2), NULL);


  gtk_grid_attach(GTK_GRID(grid), label_, 1, 5, 1, 1);


  gtk_grid_attach(GTK_GRID(grid), mainlabel0, 1, 6, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel1, 1, 7, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel2, 1, 8, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel3, 1, 9, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel4, 1, 10, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel5, 1, 11, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel6, 1, 12, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel7, 1, 13, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel8, 1, 14, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel9, 1, 15, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel10, 1, 16, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel11, 1, 17, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel12, 1, 18, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel13, 1, 19, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), mainlabel14, 1, 20, 1, 1);
  
  
  
  
  gtk_widget_show_all (window);
}

int
main (int argc, char **argv)
{
  GtkApplication *app;
  int status;

  app = gtk_application_new ("org.gtk.example", G_APPLICATION_FLAGS_NONE);
  g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
  status = g_application_run (G_APPLICATION (app), argc, argv);
  g_object_unref (app);

  return status;
}

