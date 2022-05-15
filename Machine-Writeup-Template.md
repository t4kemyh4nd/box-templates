# Acler

## Introduction

The box is designed to highlight mainly 2 things: subtle routing misconfigurations in nginx, and escaping from a custom compiled restricted shell using some overlooked bypasses for command injection vulnerabilities. 

## Info for HTB

### Access

Passwords:

| User  | Password                            |
| ----- | ----------------------------------- |
| root | &shackles |
| dave | Nothisn0tdave |
| dave-ptfs  | Deepfreeze$1336 |

### Key Processes

1. A simple Golang web server is running on port 8000 which imports the 'pprof' package.
2. Nginx is running on port 80 which forwards the requests to the aforementioned server. Basic authentication is used for most paths.
3. SSH has been updated to allow only SFTP login for the 'dave-ptfs' user.

### Automation / Crons

- One cron job is run by the root user every minute, to reset the ACLs for the /etc/shadow file. This has directly to do with the privilege escalation vector.

### Firewall Rules

Firewall is blocking direct access to port 8000, which is hosting the golang web server.

## Writeup

### Enumeration

### Nmap
```
% nmap 192.168.29.93    

Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 12:57 IST
Nmap scan report for 192.168.29.93
Host is up (0.0014s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 42.75 seconds
```

Image

We find that SSH and a web server are running on port 22 and 80 respectively.

### Web server
1. Browsing to port 80 presents us with a Basic authentication dialog.
![Screenshot 2022-05-15 at 1 03 53 PM](https://user-images.githubusercontent.com/31258575/168462272-9f62c317-dd5c-4c62-a3f6-c4724d7985ec.png)

2. We take the request to curl / burp and see that the response contains a verbose `WWW-Authenticate` header, with the message "Access restricted to goroutine debug profiler."

```
% curl -I 192.168.29.93

HTTP/1.1 401 Unauthorized
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 15 May 2022 07:29:13 GMT
Content-Type: text/html
Content-Length: 204
Connection: keep-alive
WWW-Authenticate: Basic realm="Enter password. Access restricted to goroutine debug profiler."
```

3. A simple Google search for goroutine debug profiler shows that this profiler exists usually on the /debug/pprof endpoint.
4. Visting the said endpoint does indeed give us the following page:
![Screenshot 2022-05-15 at 1 02 49 PM](https://user-images.githubusercontent.com/31258575/168462246-4f3e3991-fb0d-4531-8626-b61c3d94a95b.png)

5. All the given pages do not disclose any sensitive information, however, further searcher will reveal that this page does not show all the paths that are usually shown inside the web version of the profiler. A quick Google search for "goroutine debug profiler exploit" will show a HackerOne report showing the "cmdline" path, which discloses any command-line paramters that the go program was run with. Alternatively, the /debug/pprof endpoint can simply be bruteforced with a common wordlist, since these requests are not blocked by Basic authentication. This will also reveal the /debug/pprof/cmdline parameter:
![Screenshot 2022-05-15 at 1 07 21 PM](https://user-images.githubusercontent.com/31258575/168462390-70b049fe-3313-47bd-8018-f2ccaebe4e35.png)

6. This reveals 2 parameters, which seem to be the username and password for the basic authentication. However, this login will fail.
7. Going back to the port scan, we remember that SSH is also running on port 22. Using these credentials, we are unable to get a shell:
<img width="701" alt="Screenshot 2022-05-15 at 1 09 11 PM" src="https://user-images.githubusercontent.com/31258575/168462441-eaad4264-3db4-4396-bdcf-641052fec3cf.png">

8. This confirms that the login credentials are valid, but they cannot be used to directly login into SSH.
9. Player should now remember that there is another service, that runs on top of the SSH service: SFTP. Logging in into SFTP via the disclosed credentials is successful, and we can see a file named `nginx.conf`:

```
% sftp dave-ptfs@192.168.29.93

dave-ptfs@192.168.29.93's password: Deepfreeze$1336
Connected to 192.168.29.93.
sftp> ls
nginx.conf  
sftp> get nginx.conf
Fetching /home/nginx.conf to nginx.conf
/home/nginx.conf                                                 100%  586   146.6KB/s   00:00  
```
10. We now open this nginx.conf file, which seems to contain the configuration for the web server running on port 80:

```
% cat nginx.conf

server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;

	server_name _;

	auth_basic "Enter password. Access restricted to goroutine debug profiler.";
	auth_basic_user_file /etc/nginx/sites-available/.htpasswd;

	location /debug/pprof {
		auth_basic off;
		proxy_pass http://127.0.0.1:8000;
	}
	
	#very secure routing done here - dave
	location /daveprivateconsole {
		autoindex on;
		auth_basic off;
		alias /home/dave/server/;
	}

	location ~* ^.+user.txt$ {
		deny all;
		return 403;
	}

	location ~* ^.+/shell/.*$ {
		deny all;
		return 403;
	}
}
```

10. We see a block which uses the path /daveprivateconsole, and it servers the responses using the files in the `/home/dave/server/` directory, by making use of the `alias` directive.
11. Visiting the path in our web browser gives a simple response:
<img width="579" alt="Screenshot 2022-05-15 at 1 29 12 PM" src="https://user-images.githubusercontent.com/31258575/168463101-8cb6b715-427d-405c-b4f5-5392d92d17f0.png">

12. We can also see a comment on the alias block which hints towards exploiting this configuration. The problem here is that the location is being routed with a missing slash (/). `location /daveprivateconsole` means that anything after the "/daveprivateconsole" in the URL path will get appended to `/home/dave/server/` and the response will be served. This opens the door to a directory traversal attack.
13. By visiting the path `/daveprivateconsole../`, nginx will take "../" from the request, append it to `/home/dave/server/`, finally leading to the actual path being `/home/dave/server/../`. The response will therefore be served from the "dave" users home directory.
<img width="591" alt="Screenshot 2022-05-15 at 1 34 18 PM" src="https://user-images.githubusercontent.com/31258575/168463271-a9cd9265-59ab-47ee-8c8f-f957f61584b8.png">

14. Requests to "user.txt" and other unrequired paths have been blocked in the configuration file we disclosed above. Following this, a simple educated guess of the ".ssh" folder inside the users home directory will reveal the required SSH keys to login as the "dave" user."
<img width="597" alt="Screenshot 2022-05-15 at 1 35 44 PM" src="https://user-images.githubusercontent.com/31258575/168463314-59e32be6-e3ce-443e-ac23-9e6b41ce491d.png">

15. We simply download the SSH keys to login as the "dave" user. Following the login, we see that this is not normal shell, but looks to be some kind of custom restricted shell:
<img width="506" alt="Screenshot 2022-05-15 at 1 38 39 PM" src="https://user-images.githubusercontent.com/31258575/168463408-7d94888c-63df-408f-9425-d7089b392bc9.png">

16. We see that most commands do not work in this shell. `cat`, `ls`, `whoami` do seem to work. We also see that that trying to modify these commands to, for example, `ls -al` also gives an error saying "Command not allowed":
```
Dir: /home/dave
>>> ls -al

Command not allowed
```

17. The `ls` command does reveal that there are 2 folders and the flag inside this directory:
<img width="169" alt="Screenshot 2022-05-15 at 1 42 32 PM" src="https://user-images.githubusercontent.com/31258575/168463522-64a19445-9e68-449a-9261-ad4d33e42e06.png">
However, if we try to list the contents inside either of these folder, we are once again blocked.
18. Following this, we go heuristically from here to try and figure out how exactly the commands are being blocked. We quickly discover that the space character leads to an error.
19. In shell commands, the (IFS variable)[https://mywiki.wooledge.org/IFS] can be used as a substitution for space. We try this and find out that we are now able to list the contents of the "shell" directory, and also read the "user.txt" flag using `cat{IFS}user.txt`:
<img width="173" alt="Screenshot 2022-05-15 at 1 46 44 PM" src="https://user-images.githubusercontent.com/31258575/168463653-f8a2f949-50ab-4f23-affc-11dd183fb630.png">

20. The "shell.c" file seems to be interesting. We try to `cat` the file using the above method, and discover quickly that this is the source code of the shell that are logged into. Reading the "shell.c" file, gives 2 interesting code blocks. One which uses regex for filtering our shell input, and one that whitelists the commands that we can execute:

21. This gives a fair idea of how our shell environment works. From the whitelisted commands, we see that "chattr, chsh" and some other common commands are allowed. However, using these will lead to nothing. What we need to focus on is the "chac" string. Running "chac" in the shell says that the command is not found. However, a quick `locate chac` in any linux box leads us to the "/usr/bin/chacl" binary. Running "chacl" inside this shell results in the following:
<img width="387" alt="Screenshot 2022-05-15 at 1 53 38 PM" src="https://user-images.githubusercontent.com/31258575/168463847-d336ccfe-cd02-4d91-a5bd-b00d86f0f494.png">

22. This is where we need to do some research on what this command does. A quick man search shows that this command is used to change the ACL of files and folders onthe filesystem. When we execute the following command `ls${IFS}-l${IFS}/bin/chacl`, we discover that this binary has the SUID bit set. But it is still unclear what we can do with this command, given the whitelisted commands we can execute even following a successful ACL change.
23. We can try to make the shadow file readable using the chacl command to make it world readable (since we have SUID bit), and then try to read it's contents. We try to do this using the following command: `chacl u::r,g::r--,o::r-- /etc/shadow`. However, we discover that this command is blocked. Going back to the regex patter we disclosed earlier in "shell.c", we discover that the string "ado" has been blacklisted, meaning we can simply type in "/etc/shadow".
24. Following this, we perform another character substitution that is accepted in linux. We can replace "/etc/shadow" with "/etc/sha\*ow" (since the * character has been allowed in the regex pattern), and linux will interpret it as the shadow file. So now running the same command again, we see that we do not get any errors:

25. After this, we can simply try to read the "/etc/shadow" file, which disclosed the "root" users password. We attempt to crack this password using hashcat and the "rockyou.txt" wordlist, and are able to successfully get the password:

26. We simply use the "su" command in our restricted shell, and are able to successfully login as the root user and get the flag.
