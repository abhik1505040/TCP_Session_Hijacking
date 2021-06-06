# TCP Session Hijacker

This is a tcp session hijacking tool meant to be used for hijacking any ongoing telnet session on the same LAN. 

## Usage

### Dependencies
* Attacker machine OS -> ```Linux```

### Running the program
```bash
<Program name> <client ip> <client port> <server ip> <server port>
```
**For example**,   
```bash
g++ SessionHijacker.cpp -lpcap
sudo ./a.out 192.168.43.23 38162 192.168.43.191 23   
```
***Note:*** `<server port>` needs to be 23 (for telnet)

## Additional Resources

* [Design](Session_Hijacking_design.pdf)
* [Demo](Session_Hijacking_Report.pdf)