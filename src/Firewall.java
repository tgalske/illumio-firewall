
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Firewall {

  List<FirewallRule> rules = new ArrayList<>();

  public static void main(String[] args) {
    Firewall firewall = new Firewall("input.csv");
    System.out.println(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"));
    System.out.println(firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
    System.out.println(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
    System.out.println(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"));
  }

  public Firewall(String filePath) {
    File rulesFile = new File(filePath);
    Scanner scanner;
    try {
      scanner = new Scanner(rulesFile);
    } catch (FileNotFoundException ex) {
      System.out.println("Unable to find file in: " + filePath);
      return;
    }
    
    while (scanner.hasNext()) {
      String[] ruleElements = scanner.nextLine().split(",");
      FirewallRule newRule = new FirewallRule(ruleElements[0], ruleElements[1],
              ruleElements[2], ruleElements[3]);
      rules.add(newRule);
    }

  }

  /**
   * @param direction inbound | outbound
   * @param protocol tcp | udp
   * @param port single integer [1, 65535] or range of integers
   * @param ip_address IPv4 address in dotted notation, or range of addresses
   * @return true if there exists a rule that allows the packet
   */
  public boolean accept_packet(String direction, String protocol,
          int port, String ip_address) {
    for (int i = 0; i < rules.size(); i++) {
      FirewallRule currentRule = rules.get(i);

      // check for direction
      if (!currentRule.direction.equals(direction)) {
        continue;
      }

      // check for protocol
      if (!currentRule.protocol.equals(protocol)) {
        continue;
      }

      // check for port / port range
      if (currentRule.min_port <= port && port <= currentRule.max_port) {
        // proceed
      } else {
        continue;
      }

      // check for IP address / range of IP addresses
      // First try to convert the IP address to a long for comparing
      Long packetIP;
      try {
        packetIP = currentRule.ipToLong(InetAddress.getByName(ip_address));
      } catch (UnknownHostException ex) {
        System.out.println("Unable to parse IP address");
        return false;
      }
      if (currentRule.min_ip_address <= packetIP
              && packetIP <= currentRule.max_ip_address) {
        return true;
      }
    }

    // reject packet by default
    return false;
  }

}

class FirewallRule {

  String direction;
  String protocol;
  int min_port;
  int max_port;
  long min_ip_address;
  long max_ip_address;

  public FirewallRule(String direction, String protocol, String port,
          String ip_address) {
    this.direction = direction;
    this.protocol = protocol;

    // check if the given port has a range using regex
    String patternToSearch = "(-)";
    Pattern pattern = Pattern.compile(patternToSearch);
    Matcher matcher = pattern.matcher(port);
    if (matcher.find()) {
      // there is a range of ports
      // split string at dash character
      String[] range = port.split("-");
      this.min_port = Integer.parseInt(range[0]);
      this.max_port = Integer.parseInt(range[1]);
    } // port is just one integer
    else {
      this.min_port = Integer.parseInt(port);
      this.max_port = Integer.parseInt(port);
    }

    // check if the given IP address has a range using regex
    // use existing regex objects from above
    matcher = pattern.matcher(ip_address);
    if (matcher.find()) {
      // Rule has a range of IP addresses
      String[] range = ip_address.split("-");
      try {
        this.min_ip_address = ipToLong(InetAddress.getByName(range[0]));
        this.max_ip_address = ipToLong(InetAddress.getByName(range[1]));
      } catch (UnknownHostException ex) {
        System.out.println(ex);
      }

    } // Rule has just one IP address
    else {
      // attempt to convert IP Adddress (String) to long for comparison
      try {
        this.min_ip_address = ipToLong(InetAddress.getByName(ip_address));
        this.max_ip_address = ipToLong(InetAddress.getByName(ip_address));
      } catch (UnknownHostException ex) {
        System.out.println(ex);
      }

    }

  }

  /**
   * @see https://stackoverflow.com/questions/4256438/calculate-whether-an-ip-address-is-in-a-specified-range-in-java
   */
  public final long ipToLong(InetAddress ip) {
    byte[] octets = ip.getAddress();
    long result = 0;
    for (byte octet : octets) {
      result <<= 8;
      result |= octet & 0xff;
    }
    return result;
  }

}
