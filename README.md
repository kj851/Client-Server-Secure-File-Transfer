Program Usage and Methods:  

To run client: ./client 127.0.0.1 9000 127.0.0.1 9001 example.txt (Filled with the file in downloads) 

To run server: ./server 9000 

To run the program, you must first create a client and server pub/priv key. This can be done in bash using openssl genpkey and openssl RSA commands. The keys must explicitly be called server_pub/priv.pem and client_pub/priv.pem for the program to function. There must also be a directory called “downloads” for the server to transfer to the client. I have created a makefile to streamline the compilation project since multiple libraries are used. I also included extensive error checking to assist when users run into issues. Since the RSA signing can be tricky, I added specific openssl errors codes if it fails. Two instances of a command line must be running to execute the server and client code. 

 

Code Development Methods:  

To correctly implement SHA-256 with HMAC for authentication, I had to understand the fundamentals of RSA and how the handshake would be completed using HMAC. I authenticated the server using a nonce which would prevent replay attempts. I decided to use fopen to authenticate all the keys with an error check. I used various code samples to help me understand which functions to use and debug the file server. After my research of my chosen hashing algorithm and cryptographic method, I was able to move on to the failover system and how error checking was going to work.  
