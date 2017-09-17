#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define bool int
#define true 1
#define false 0
#define SALT "NaCl"
#define ITERATIONS 4096
#define KDF_KEY_SIZE 16

int encrypt();
char *out_file_name;

int main(int argc, char *argv[])
{

	if (argc != 3 && argc != 4)
	{
		printf("Invalid number of parameters\n");
		return -1;
	}
	else
	{
		out_file_name = (char *)malloc(strlen(argv[1])+3);
		strcat(out_file_name,argv[1] );
		strcat(out_file_name,".uf" );

		if (strcmp(argv[2], "-l") == 0)
		{
			encrypt(argv, false);
		}
		else if (strcmp(argv[2], "-d") == 0)
		{
           encrypt(argv, true);
		}
		else
			printf("Invalid parameters\n");
	}
return 0;
}

int encrypt(char *argv[], bool transfer_needed)
{
	char pass[100], key[16];
	char *file_buffer, *ecrypted_file_buffer;
	int len = 0;
	int sucess = 0;
	FILE *input_fp, *output_fp, *output_fp2;
	
	
	printf("Beginning encryption\n");
	printf("Please enter password\n");
	scanf("%s", &pass);
	
    printf("Pass: %s", pass);
	
	
	gcry_kdf_derive(pass,
                        strlen(pass),
                        GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA512,
                        SALT,
                        strlen(SALT),
                        ITERATIONS,
                        16,
                        key);
			
    if (strlen(key) == 0)
	{
		printf("Error: Generating key, exiting...\n");
		return -1;
	}	

	//printf("Key: ");
	for(int i = 0; i < 16; i++)
		printf("%02X ",(unsigned char) key[i]);
	printf("\n");

    //File operations
	input_fp=fopen(argv[1], "rb"); 
	if (!input_fp) {
  		printf("Error: Opening file, exiting...\n");
  		return -1;
	}
	
	//Get file size
	fseek(input_fp, 0, SEEK_END);
	int file_size = ftell(input_fp);
	
	printf("Debug file size 1 : %d", file_size);
        if (0)
        if (file_size % 16 != 0)
        {
            fclose(input_fp);
            FILE *fp = fopen(argv[1], "a+");
            fseek(fp, 0, SEEK_END);
            for (int i=0; i < 16 - (file_size % 16); i++)
                fputc('\0',fp);
            fclose(input_fp);
            input_fp = fopen(argv[1], "rb");
            file_size += (file_size % 16);
            
        }
        
        fseek(input_fp, 0, SEEK_END);
	file_size = ftell(input_fp);
        fseek(input_fp, 0, SEEK_SET);
	
	printf("Debug file size 2 : %d", file_size);
            
	//file_size = file_size % 16 == 0 ? file_size : 16 * (file_size/16) + 16;
	
        int mod = file_size % 16;
        int pad = 16 - mod;

            
         
printf("Debug File \n");
	file_buffer = (char *) malloc ((file_size + pad) * sizeof(char));
	ecrypted_file_buffer = (char *) malloc ((file_size + pad) * sizeof(char));
	fseek(input_fp, 0, SEEK_SET);
	fread(file_buffer, sizeof(char), file_size, input_fp);
        
        //Fix size
        printf("Debug data 00 : %c\n", file_buffer[file_size]);
        printf("Debug data 01 : %c\n", file_buffer[file_size-1]);
        printf("Debug data 2 : %c\n", file_buffer[file_size-2]);
        
        //int mod = file_size % 16;
        if (mod != 0)
        {
            char temp = file_buffer[file_size];
            for (int i=0; i < 16 - mod; i++)
            {
                file_buffer[file_size++] = '\0';
            }
            file_buffer[file_size] = temp;
            
        }
        printf("Debug file size 3 : %d", file_size);

printf("Debug En \n");	
	//Begin encrytion
	gcry_cipher_hd_t g_cipher_handle;
	gcry_error_t g_err;

	char *hmac;



printf("Debug Ci \n");
	g_err = gcry_cipher_open(&g_cipher_handle, GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_SECURE);
printf("Debug Ci 1\n");
    g_err = gcry_cipher_setkey(g_cipher_handle, key, 16);	
printf("Debug Ci 2\n");
int IV[16] = {5844};
    g_err = gcry_cipher_setiv(g_cipher_handle, &IV, 16);
	
printf("Debug Ci 3\n");
    g_err = gcry_cipher_encrypt(g_cipher_handle, ecrypted_file_buffer, file_size, file_buffer, file_size);
	//Change this
    if(g_err != 0){
		//printf ("Error at encrypting:%s %s\n",gcry_strerror(status_encrypt),gcry_strerror(status_encrypt));
		exit(-11);
	}


	//Generate the hmac
	if (0)
	{
		printf("Debug HMAC \n");
		gcry_error_t err;
		gcry_md_hd_t md;
		err = gcry_md_open(&md, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE);
		if(err != GPG_ERR_NO_ERROR){
			printf ("Error at opening handle for hmac: %s\n",gcry_strerror(err));
			exit(-1);
		}
		err = gcry_md_enable(md,GCRY_MD_SHA512);
		err = gcry_md_setkey(md, key,16);
		if(err != GPG_ERR_NO_ERROR){
			printf ("Error at setting key: %s\n",gcry_strerror(err));
			exit(-1);
		}
		// generating the HMAC using the cipher text
		gcry_md_write(md,ecrypted_file_buffer,file_size);
		gcry_md_final(md);
		// printf("\nlength: %lu\n",length);


		hmac = gcry_md_read(md , GCRY_MD_SHA512 );
		if(hmac == NULL ){
			printf ("hmac null ?\n");
			// exit(-1);
		}
		// print_buf(hmac,64); // debug
		// printf("hmac length : %lu\n",strlen(hmac)); // debug to check hmac length should be 64	
	}
	
	//Save the file
	{
		
printf("Debug File 2 \n");
	if( access( out_file_name, F_OK ) != -1 ) {
	   	printf ("File already present\n");
	    return 33;
	} 
		output_fp = fopen(out_file_name,"wb");
		if (output_fp){
		// buff is encrypted content and hmac is HMAC generated
		fwrite(ecrypted_file_buffer, file_size, sizeof(char), output_fp);
                if (0)
		fwrite(hmac, 64 , sizeof(char), output_fp);
		// added + 1 for the trailing char. just to finish the writing to file properly
		// basically writes a null value to the end.
		// output is equal to encrypted content length + HMAC length.
		
		//Clean this
		fclose(input_fp);
	}
	else{
		printf ("Error at opening file to write\n");
		exit(-1);
	}
	}
	printf("Successfully encrypted the inputfile to %s\n",out_file_name);
	fclose(output_fp);
	
	printf("Debug Trans \n");
	//Transfer if needed
	if (transfer_needed)
	{
		output_fp = fopen(out_file_name,"rb");
		int sockfd; // socket handler 
		struct sockaddr_in dest_sock_addr; // server address 
		char *ip, *port; 

		// Open the socket handler to use it to connect to server
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)
		{	
			//checking for errors in Init
			printf("Error : Could not create socket (Check whether you have added all libraries) \n");
				fclose(output_fp);
			exit(-1);
		}
		
		printf("Debug Trans 1\n");
	
		
	ip	 = strtok(argv[3],":");
	port = strtok(NULL, ":");
		int PORT = atoi(port); // casting the global variable char to int

		/* Initialize server properties by using ip and port from the args */
		dest_sock_addr.sin_family = AF_INET;
		dest_sock_addr.sin_port = htons(PORT); // port convertion from host byte order to network byte order.
		dest_sock_addr.sin_addr.s_addr = inet_addr(ip); // easy way to convert it to a valid format
		

		// Connect to the socket using the handler
		if(connect(sockfd, (struct sockaddr *)&dest_sock_addr, sizeof(dest_sock_addr))<0)
			{
				// happens when it fails to connect to the server.
				printf("\n Error in establishing connection to Server\n");
					fclose(output_fp);
				exit(-1);
				// configure the exit parameters to whatever code we want in future.
			}

		printf("Transmitting to %s:%s\n",ip,port);
		while(1){
        unsigned char buff[256]={0};
        int nread = fread(buff,1,256,output_fp);
        if(nread > 0)
        {			
            write(sockfd, buff, nread);
			printf("Debug Socket Data Sent");
        }
        if (nread < 256){break;}
    }
    printf("Successfully sent the file\n");
		fclose(output_fp);
    }	

	}

