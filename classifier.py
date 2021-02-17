'''
Get two iput CSV files rules and commuincaitons
Produce classifications for every line in the communication file 
'''

from collections import namedtuple
import netaddr


def subnet_match(ip_address, subnet):
    '''
    https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
    '''
    return netaddr.IPAddress(ip_address) in netaddr.IPNetwork(subnet)

Communication = namedtuple('Communication', ["id", "timestamp", "device_id", "protocol_name", "host"])

class RuleCommunicatingProtocol():
    def __init__(self, id, protocol_name, classification):
        self.id, self.protocol_name = id, protocol_name
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
    def __init__(self, id, ip_address, classification):
        self.id, self.ip_address = id, ip_address
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
    def __init__(self, id, subnet, classification):
        self.id, self.subnet = id, subnet
        self.classification = classification
        
    @staticmethod
    def type():
        return "communicating_with_subnet"

    def match(self, communication):
        if subnet_match(communication.ip_address, == self.subnet):
            return self.classification
        return None


class RuleCommunicatingWithDomain():
    '''
    IPv4 only
    '''
    def __init__(self, id, domain, classification):
        self.id, self.domain = id, domain
        self.classification = classification
        
    @staticmethod
    def type():
        return "communicating_with"

    def match(self, communication):
        if subnet_match(communication.ip_address, == self.subnet):
            return self.classification
        return None

rules_classes = [RuleCommunicatingProtocol, RuleCommunicatingWith, RuleCommunicatingWithSubnet, RuleCommunicatingWithDomain]
rules_by_type = {}
for rule in rules_classes:
    rule_type = rule.type()
    rules_by_type[rule_type] = rule

def loadRules(rulesFile):
    rules = []
    for line in rulesFile:
        fields = line.split(",")
        id = fields[0]
        rule_type = fields[1]
        argument = fields[2]
        classification = fields[3]

        rule_cass = rules_by_type[rule_type]
        rule = rule_cass(id, argument, classification)
        rules.append(rule)

    return rules

def main():
    rulesFile = open(sys.argv[1], 'r')
    rules = loadRules(rulesFile)
    rulesFile.close()

    communicationsFile = open(sys.argv[2], 'r')
    classificationsFile = open(sys.argv[3], 'w')
    processCommunications(rules, communicationsFile, classificationsFile)
    communicationsFile.close()
    classificationsFile.close()
    
if __name__ == "__main__":
    main()




