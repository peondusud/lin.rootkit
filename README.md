lin.rootkit
===========
To build the module :
$> make

To load the module :
$> insmod rootkit.ko

Check the module is loaded :
$> lsmod

To remove the module :
$> rmmod rootkit

Check the rootkit messages : 
tail -f /var/log/kern.log

The features of our rootkit : 
=============================

- A root access (with kill -x yzx) 

- Hide the module from the module list 

- Hide the files that begin with _root_ 

- Hide executables launched by the hacker (2 pts)

- Create a keylogger (3 pts)

- Hide a part of a file contents(between two tags : ---ROOT---) (3 pts)

- Hide network connections of the hacker (3 pts)

- Modify  the frames of the network connection (inject some data in http frames) (5 pts)

- Create a backdoor and a reverse shell (5 pts) 
  A reverse shell allows the hacker to get a remote shell from the hacked machine

- Create a analyzer to get passwords and logins from the keylogger and the network 
  (internet access, e-mail,  password of the session) and the user/password found via the network (5 pts)



Project : (40% 32 bits - 40% 64 bits - 20% Style (ident; comments; readability; no warning))


The rootkit must compile and run on a 32 AND 64 bits machines;
The hacker when he uses the hacked machine can :
- watch the hidden networks 
- list the hidden files
- list the hidden processus
- print the contents hidden in the files
- delete the module
And his actions are not logged by the keylogger
