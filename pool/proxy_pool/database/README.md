# 数据库架构

###　DB：HostInfo

- host String（max 256） like www.baidu.com or 192.182.4.0 and support * like 192.182.4.*
- port_sum (int)  nmap scan port sum  
- mode(int) 0: ip  1: host  2: ip + *
- insert_at
- update_at
- cost_second (int) complete it cost

### DB: IPInfo

- ip String( max 16)
- port_sum (int)  port sum 
- country(null)
- province(null)
- city(null)
- district(null)
- operator(null)
- insert_at
- update_at

 
### DB: Proxy

- host Foreign Key(HostInfo)
- ip Foreign Key(IPInfo)
- port (int)
- state (int) nmap scan state(open, closed, filtered, unfiltered, open|filtered, closed|filtered) 
- is_proxy (boolean)
- is_checked(boolean)
- checked_state (int)(0: default, 1: Transparent Proxy 2:Anonymous Proxy 3:High Anonymous Proxy 4:Need Auth Proxy) 
- protocol (int) (0:default 1:http 2:https 3:http+https 4:socks)
- insert_at
- update_at

