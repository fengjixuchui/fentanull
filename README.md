```
 (           )                   )       (    (     
 )\ )     ( /(  *   )   (     ( /(       )\ ) )\ )  
(()/( (   )\()` )  /(   )\    )\())   ( (()/((()/(  
 /(_)))\ ((_)\ ( )(_)((((_)( ((_)\    )\ /(_))/(_)) 
(_))_((_) _((_(_(_()) )\ _ )\ _((_)_ ((_(_)) (_))   
| |_ | __| \| |_   _| (_)_\(_| \| | | | | |  | |    
| __|| _|| .` | | |    / _ \ | .` | |_| | |__| |__  
|_|  |___|_|\_| |_|   /_/ \_\|_|\_|\___/|____|____| 
```
# fentanull 
fentanull is a LKM ring0 rootkit loosely based off of [diamorphine].(https://github.com/m0nad/diamorphine) (haha, get it? cuz fentanyl is an analogue of heroin, nvm ill shut up now.) This is a work in progress: I will be continuously adding more features as time goes on. 

# how it works 


# to-do list 
- [ ] Implement anti-RE features 
	- [ ] String obfuscation (probably only going to be stack strings + xor because I'm lazy )
	- [ ] VM detection 
	- [ ] ???
- [ ] Hook more syscalls (only open is hooked for now)
	- [ ] read 
	- [ ] kill 
	- [ ] execve 
	- [ ] getdents\* 
	- [ ] socket
	- [ ] accept 
- [ ] Implement backdoor (no idea what im gonna be using for now)
- [ ] Persistence (coming v soon)
- [ ] Network hiding 
- [ ] Clean up code 
- [ ] ??? 
- [ ] Profit 
