# banSASLSpam
Reads mail logs and bans SASL login spammers

This works on Rocky 9 server and probably any clone or derivative. 
Uses perl with no additional modules. Requires pflogsumm and firewalld as helpers. 

Searches the mail logs for "SASL (PLAIN|LOGIN) authentication failed" and "does not resolve to address", 
then uses rich rules to ban detected IPs on ports 25 and 587 (smtp submission).

You may wish to adjust the ban thresholds at the top of the script. 

USAGE: run the script with no flags for interactive use. 
Add a space and a 'y' to run without interaction. 
Add a space and a 'b' to just see the list of banned IPs. 
