import sys
from collections import namedtuple
import netaddr
import IPy

# simple cache
reversed_names = {}
def host_from_address(ip_address):
    if ip_address in reversed_names:
        return reversed_names[ip_address]

    ip = IPy.IP(ip_address)
    domain = ip.reverseName()
    # cache the result
    reversed_names[ip_address] = domain
    return domain

def subnet_match(ip_address, subnet):
    '''
    https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
    '''
    return netaddr.IPAddress(ip_address) in netaddr.IPNetwork(subnet)

Communication = namedtuple('Communication', ["id", "timestamp", "device_id", "protocol_name", "host"])

class RuleCommunicatingProtocol():
    def __init__(self, rule_id, protocol_name, classification):
        self.rule_id, self.protocol_name = rule_id, protocol_name
        self.classification = classification

    @staticmethod
    def type():
        return "communicating_protocol"

    def match(self, communication):
        if communication.protocol_name == self.protocol_name:
            return self.classification
        return None
        

class RuleCommunicatingWith():
    '''
    IPv4 only
    '''
    def __init__(self, rule_id, ip_address, classification):
        self.rule_id, self.ip_address = rule_id, ip_address
        self.classification = classification
        
    @staticmethod
    def type():
        return "communicating_with"

    def match(self, communication):
        if communication.ip_address == self.ip_address:
            return self.classification
        return None

class RuleCommunicatingWithSubnet():
    '''
    IPv4 only
    '''
    def __init__(self, rule_id, subnet, classification):
        self.rule_id, self.subnet = rule_id, subnet
        self.classification = classification
        
    @staticmethod
    def type():
        return "communicating_with_subnet"

    def match(self, communication):
        if subnet_match(communication.ip_address, self.subnet):
            return self.classification
        return None


class RuleCommunicatingWithDomain():
    '''
    IPv4 only
    '''
    def __init__(self, rule_id, domain, classification):
        self.rule_id, self.domain = rule_id, domain
        self.classification = classification
        
    @staticmethod
    def type():
        return "communicating_with_domain"

    def match(self, communication):
        domain = host_from_address(communication.ip_address)
        if domain == self.domain:
            return self.classification
        return None

rules_classes = [RuleCommunicatingProtocol, RuleCommunicatingWith, RuleCommunicatingWithSubnet, RuleCommunicatingWithDomain]
rules_by_type = {}
for rule in rules_classes:
    rule_type = rule.type()
    rules_by_type[rule_type] = rule

def get_rule_id(rule): return rule.rule_id

def load_rules(rulesFile):
    rules = []
    for line in rulesFile:
        fields = line.split(",")
        rule_id = int(fields[0])
        rule_type = fields[1]
        argument = fields[2]
        classification = fields[3]

        rule_class = rules_by_type[rule_type]
        rule = rule_class(rule_id, argument, classification)
        rules.append(rule)
        
    # sort by rule_id
    rules.sort(key=get_rule_id)

    return rules

def process_communication(rules, communication):
    result = "unknown"
    for rule in rules: # rules are ordered by ID
        classification = rule.match(communication)
        if classification != None:
            result = classification
    return result

def process_communications(rules, communications_file, classifications_file):
    classifications = {}
    line_idx = 1
    for line in communications_file:
        fields = line.split(",")
        communication_id = fields[0]
        timestamp = fields[1]
        device_id = fields[2]
        protocol_name = fields[3]
        host = fields[4]
        communication = Communication(communication_id, timestamp, device_id, protocol_name, host)
        classification = process_communication(rules, communication)
        # I store the last classification
        classifications[device_id] = classification
        line_idx += 1

    for device_id, classification in classifications.items():
        classifications_file.write(f"{line_idx},{device_id},{classification}\n")

def main():
    rules_file = open(sys.argv[1], 'r')
    rules = load_rules(rules_file)
    rules_file.close()

    communications_file = open(sys.argv[2], 'r')
    classifications_file = open(sys.argv[3], 'w')
    process_communications(rules, communications_file, classifications_file)
    communications_file.close()
    classifications_file.close()
    
if __name__ == "__main__":
    main()
