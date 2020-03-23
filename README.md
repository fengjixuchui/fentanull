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
[![Starred](https://img.shields.io/github/stars/blacchat/fentanull.svg)](https://github.com/blacchat/fentanull)

# fentanull 
fentanull is a LKM ring0 rootkit loosely based off of [diamorphine](https://github.com/m0nad/diamorphine) (haha, get it?) This is a work in progress: I will be continuously adding more features as time goes on. 

# WARNING 
I am not a great programmer, and I am not one of those guys in cargo shorts and open-toed sandals who knows Linux better than they know themselves. This is merely a PoC/practice for me and might seriously fuck up your system: currently, it crashes my host Arch install but works fine on lxubuntu. Do not do anything with this unless you know what you are doing. 

# Issues 
- Potential race condition in how the WP bit in cr0 is set, will fix with some inline asm magic later  

# features 
- 2 (two!!!!) ways of writing to read-only pages 
- File hiding by prefixing files with "hideme-"

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

# installation 
```
sudo make clean 
sudo insmod fentanull.ko hook_type={1, 0}
``` 

