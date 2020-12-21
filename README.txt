Readme

Setup:
1) Clone the kernel from github and checkout the kernel v5.8.
2) Apply the patch kernel_secure_DSM.patch on the root of the kernel directory.
3) For compiling applications just make. 

Testing :
1) Execute the server with only port parameters. Ex : ./application -p 1234
2) Execute client with port and ip address. Ex: ./application -p 1234 -i 192.168.0.120
3) Now the DSM is established. We can read and write data and synchronize between the two systems.
4) You can observe verification of signatures through debug prints.

Attack:
1) Execute the synflood.c file for executing a SYN flood attack using - ./synflood 127.0.0.1 5200 (Port number binded to Server)
   Validate the spam on the corresponding port using - sudo tshark -i lo 
2) Execute the TCP rest attack by using the command python tcp-reset.py