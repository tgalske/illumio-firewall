# illumio-firewall
Given a set of firewall rules, a network packet will be accepted by the firewall if and only if the direction, protocol, port,
and IP address match at least one of the input rules.

The first thought I had when thinking through the program is which data type to use to store the firewall rules. I decided on
an arraylist since it's quick to implement and I could compare the current rule to the packet for each iteration. The downside
is that finding a rule can take O(n) time. If I had more time, I'd create two separate lists: one for inbound and one for outbound.
I'm not sure how I'd implement this in code, but ordering the rules from most commonly used to least commonly used can help
with performance (perhaps adding a weight to each rule). It would also be useful to add checks in the FirewallRule class so
invalid rules (unsupported protocols, ports, IP addresses) are thrown away. I'd consider replacing the for-loop in the
`accept_packet()` method with a Java stream.

The solution is written in Java and consists of two classes: `Firewall` and `FirewallRule` where a `Firewall` object
contains a list of type `FirewallRule`.

### Class: Firewall
| Property  | Datatype |
| ------------- | ------------- |
| List | FirewallRule |

### Class: FirewallRule
| Property  | Datatype | Options / Examples | Notes
| ------------- | ------------- | ---------| ----- |
| direction  | String  | `inbound` or `outbound` | |
| protocol  | String  | `tcp` or `udp` | |
| min_port | int | `20` | Can be the same as max_port |
| max_port | int | `22` | Can be the same as min_port | 
| min_ip_address | long | see section below | Can be the same as max_ip_address |
| max_ip_address | long | see section below | Can be the same as min_ip_address |


### Minimum and Maximum IP addresses
When thinking ahead to comparing the incoming packet to a rule, I knew comparing the direction, protocol, and port number(s)
wouldn't be an issue. However, I was unsure about comparing IP addresses. A quick search on StackOverflow
[returned a solution](https://stackoverflow.com/questions/4256438/calculate-whether-an-ip-address-is-in-a-specified-range-in-java)
I could use with one method. All IP addresses would be converted from strings to longs so they can be compared.

### Testing
Unfortunately I ran out of time to conduct custom test cases. However, my solution returned correct results for the test cases
provided. If I had more time, I'd:
1) Stress test where I'd add thousands of rules and send a packet I know would get rejected to see
how quickly the program is
2) Test against packets with invalid IP addresses (275.168.1.1)
3) Test for packets with ports of 0, 1, 65535, and 65536
4) Test for packets with an IP address one below or above the rule (packet IP: 192.168.1.1, allowed IP: 192.168.1.2)


### Desired Team
Platform
