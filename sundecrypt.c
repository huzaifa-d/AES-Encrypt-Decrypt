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

int dcrypt();
void start_listening(int port);
char *out_file_name;
char *in_file_name = "recieved.file";

int main(int argc, char *argv[])
{

	if (argc != 3 && argc != 4)
	{
		printf("Invalid number of parameters\n");
		return -1;
	}
	else
	{

		if (strcmp(argv[2], "-l") == 0)
		{
			return dcrypt(argv, false);
		}
		else if (strcmp(argv[2], "-d") == 0)
		{
		   int port = atoi(argv[3]);
           start_listening(port);
           return dcrypt(argv, true);
		}
		else
		{
			printf("Invalid parameters\n");
			return -1;
		}
	}
return 0;
}

void start_listening(int port)
{

	int server_fd;
    int in_socket;	
	
    FILE *f_out;
    f_out = fopen(in_file_name, "w+b"); 
    if(!f_out)
    {
        printf("Error opening file");
        error(-1);
        
    }

    
    struct sockaddr_in serv_addr , client_addr;
    int addrlen = sizeof(client_addr);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0)
    {
        printf("\n Error : Could not create socket \n");
        return -1;
    }


    int bytesReceived = 0;
    char recvBuff[256];
    memset(recvBuff, '0', sizeof(recvBuff));


    // Setting up the server properties 
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);
	

	if(bind(server_fd, (struct sockaddr*)&serv_addr,sizeof(serv_addr)) < 0){
		printf("\n Error : Bind error \n");
		close(server_fd);
        return -1;
	}


    listen(server_fd, 1);

    printf("Waiting for connections.\n");
	while(1)
    {
    	// Accept the connection and give us a socket handler
    	in_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
	    //Read on the socket handler continously by 256
	    printf("Inbound File.\n");
	    while((bytesReceived = read(in_socket, recvBuff, 256)) > 0)
	    {
	        fwrite(recvBuff, 1,bytesReceived,f_out);
			printf("Debug Socket Data Written");
	        if(bytesReceived < 256)
		    {
		        printf("Received successfully \n");
		        close(in_socket);
		        fclose(f_out);
		        return;
		    }
	    }
	    close(in_socket);
    }
	
    do
    {
    	// Accept the connection and give us a socket handler
    	in_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
	    //Read on the socket handler continously by 256
	    printf("Inbound File.\n");
	    while((bytesReceived = read(in_socket, recvBuff, 256)) > 0)
	    {
	        fwrite(recvBuff, 1,bytesReceived,f_out);
	        if(bytesReceived < 256)
		    {
		        printf("Received successfully \n");
		        close(in_socket);
		        fclose(f_out);
		        return;
		    }
	    }	    
    }while (0);
	close(in_socket);
	fclose(f_out);
}


int dcrypt(char *argv[], bool recieve_file)
{
	char pass[100], key[KDF_KEY_SIZE];
	char *file_buffer, *hmac_buffer, *decrypted_file_buffer;
	int len = 0;
	int sucess = 0;
	FILE *input_fp, *output_fp;
			gcry_error_t err;
		gcry_md_hd_t md;
		
	char *hmac_dec;
	int IV[KDF_KEY_SIZE] = {5844};
	
	out_file_name = (char *)malloc(strlen(argv[1])+3);
	strcat(out_file_name,argv[1] );
	strcat(out_file_name,".uf" );

	
	printf("Beginning Decryption\n");
	printf("Please enter password\n");
	scanf("%s", &pass);

	
	gcry_kdf_derive(pass, strlen(pass), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT,
                        strlen(SALT),
                        ITERATIONS,
                        KDF_KEY_SIZE,
                        key);
			
    if (!strlen(key))
	{
		printf("Error: Generating key, exiting...\n");
		return -1;
	}		
	

	//printf("Key: ");
	for(int i = 0; i < KDF_KEY_SIZE; i++)
		printf("%02X ",(unsigned char) key[i]);
	printf("\n");

    //File operations
	if (!recieve_file)
	{
	input_fp=fopen(argv[1], "r"); 
	if (!input_fp) {
  		printf("Error: Opening file, exiting...\n");
  		return -1;
	}
	}
	else
	{
			input_fp=fopen(in_file_name, "rb"); 
	if (!input_fp) {
  		printf("Error: Opening file, exiting...\n");
  		return -1;
	}
	}
	
	//Get file size
	fseek(input_fp, 0, SEEK_END);
	//Removing the HMAC
	int file_size = ftell(input_fp);
	printf("Debug file size 1 : %d", file_size);        
	
	
	
	
printf("Debug File \n");
	file_buffer = (char *) malloc (file_size * sizeof(char));
	hmac_buffer = (char *) malloc (64);
	
	fseek(input_fp, 0, SEEK_SET);
	fread(file_buffer, sizeof(char), file_size, input_fp);
	fseek(input_fp, -65, SEEK_END);
	fread(hmac_buffer,sizeof(char),64,input_fp);
	

printf("Debug De \n");	
	//Begin decrytion
	gcry_cipher_hd_t g_cipher_handle;
	gcry_error_t g_err;



printf("Debug Ci \n");
	g_err = gcry_cipher_open(&g_cipher_handle, GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_SECURE);
	if(g_err != GPG_ERR_NO_ERROR)
	{
		printf ("Error: Getting a cipher handle, exiting...\n", gcry_strerror(g_err));
		return -1;
	}

printf("Debug Ci 1\n");
    g_err = gcry_cipher_setkey(g_cipher_handle, key, KDF_KEY_SIZE);
	
printf("Debug Ci 2\n");

    g_err = gcry_cipher_setiv(g_cipher_handle, &IV, KDF_KEY_SIZE);
	
printf("Debug Ci 3\n");
decrypted_file_buffer = (char *) malloc (file_size);
    g_err = gcry_cipher_decrypt(g_cipher_handle, decrypted_file_buffer, file_size, file_buffer, file_size);
    if(g_err != 0)
	{
		printf ("Error: During decryption %s\n",gcry_strerror(g_err));
		return -1;
	}

printf("Debug HMAC \n");
	//Generate the hmac
	{

		err = gcry_md_open(&md, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE);

		printf("Debug HMAC 1\n");
		err = gcry_md_enable(md,GCRY_MD_SHA512);
		err = gcry_md_setkey(md, key,KDF_KEY_SIZE);

		printf("Debug HMAC 2\n");

		gcry_md_write(md,decrypted_file_buffer,file_size);
		gcry_md_final(md);


		printf("Debug HMAC 3\n");
		hmac_dec = gcry_md_read(md , GCRY_MD_SHA512 );
	}
	
	//Compare HMAC
	{
		printf("Debug HMAC 4\n");
		if (!strcmp(hmac_buffer, hmac_dec))
		{
			printf("HMACs Differ! Halt!");
			return -1;
		}
	}
	
	//Save the file	
	{
			
	printf("Debug File 2 \n");
		if( access( out_file_name, F_OK ) != -1 ) {
			printf ("File already present\n");
			return 33;
		} 
			output_fp = fopen(out_file_name,"w");
			if (output_fp){ 
			while (decrypted_file_buffer[file_size-1] == '\0')
			{
				file_size--;
			}        
			fwrite(decrypted_file_buffer, file_size, sizeof(char), output_fp);
			fclose(output_fp);
			fclose(input_fp);
		}
		else{
			printf ("Error at opening file to write\n");
			return -1;
		}
		}
		printf("Successfully decrypted the input file to %s\n",out_file_name);
	
	//Transfer if needed
	{
		
	}
	
	return 0;
}
