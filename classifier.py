import sys
from collections import namedtuple
import netaddr
import IPy
import multiprocessing
import threading


CommunicationEvent = namedtuple('CommunicationEvent', ["id", "timestamp", "device_id", "protocol_name", "host"])

class RuleCommunicatingProtocol():
    def __init__(self, rule_id, protocol_name, classification):
        self.rule_id, self.protocol_name = rule_id, protocol_name
        self.classification = classification

    @staticmethod
    def type():
        return "communicating_protocol"

    def match(self, communication_event):
        if communication_event.protocol_name == self.protocol_name:
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

    def match(self, communication_event):
        if communication_event.host == self.ip_address:
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

    @staticmethod
    def subnet_match(ip_address, subnet):
        '''
        https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
        '''
        return netaddr.IPAddress(ip_address) in netaddr.IPNetwork(subnet)

    def match(self, communication_event):
        if RuleCommunicatingWithSubnet.subnet_match(communication_event.host, self.subnet):
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

    # simple cache
    reversed_names = {}
    @staticmethod
    def host_from_address(ip_address):
        rcwd = RuleCommunicatingWithDomain
        if ip_address in rcwd.reversed_names:
            return rcwd.reversed_names[ip_address]

        ip = IPy.IP(ip_address)
        domain = ip.reverseName()
        # cache the result
        rcwd.reversed_names[ip_address] = domain
        return domain

    def match(self, communication_event):
        domain = RuleCommunicatingWithDomain.host_from_address(communication_event.host)
        if domain == self.domain:
            return self.classification
        return None

rules_by_type = {}

def init_rules():
    rules_classes = [RuleCommunicatingProtocol, RuleCommunicatingWith, RuleCommunicatingWithSubnet, RuleCommunicatingWithDomain]
    for rule in rules_classes:
        rule_type = rule.type()
        rules_by_type[rule_type] = rule

def get_rule_id(rule): return rule.rule_id

def read_csv_line(input_file):
    '''
    read the file, yield fields of the CSV
    Use pandas?
    '''
    for line in input_file:
        fields = line.split(",")
        result = []
        for f in fields:
            f = f.strip()
            result.append(f)
        yield tuple(result)

def load_rules(rules_file):
    '''
    Read the file line by line, collect rules in a list
    '''
    rules = []
    for fields_tuple in read_csv_line(rules_file):
        rule_id_s, rule_type, argument, classification = fields_tuple
        rule_id = int(rule_id_s)
        rule_class = rules_by_type[rule_type]
        rule = rule_class(rule_id, argument, classification)
        rules.append(rule)
        
    # sort by rule_id
    rules.sort(key=get_rule_id)

    return rules

def process_communication(rules, communication_event):
    '''
    Apply all rules to the communication_event
    '''
    result = None
    for rule in rules: # rules are ordered by ID
        classification = rule.match(communication_event)
        if classification != None:
            result = classification
    return result

devices_classifications = {}

# For parallel execution I need a processing queue for every device_id
# https://stackoverflow.com/questions/16857883/need-a-thread-safe-asynchronous-message-queue
devices_queues = {}

def process_communication_job(device_id, rules):
    '''
    Apply all rules to the communication event for a specific device
    '''
    device_queue = devices_queues[device_id]
    (communication_event, line_idx) = device_queue.get()
    classification = process_communication(rules, communication_event)
    # I store the last classification
    if not device_id in devices_classifications:
        if classification == None:
            classification = "unknown"
        devices_classifications[device_id] = (classification, line_idx)
    if classification != None:
        devices_classifications[device_id] = (classification, line_idx)

def csv_row_to_communication_event(fields):
    communication_id, timestamp, device_id, protocol_name, host = fields
    communication_event = CommunicationEvent(communication_id, timestamp, device_id, protocol_name, host)
    return communication_event

def process_communications(rules, communications_file, classifications_file):
    '''
    Read the file line by line
    Push every communication event to the corresponding queue. There is one queue for
    every device 
    The end result is devices_classifications map of classified devices 
    '''
    line_idx = 1
    jobs = []
    for fields_tuple in read_csv_line(communications_file):
        communication_event = csv_row_to_communication_event(fields_tuple)
        device_id = communication_event.device_id
        if not device_id in devices_queues:
            devices_queues[device_id] = multiprocessing.Queue()
        device_queue = devices_queues[device_id]
        device_queue.put((communication_event, line_idx))
        # I create a thread for every communication event
        # I do not have to. I can use a limited pool of jobs
        job = threading.Thread(target=process_communication_job, args=(device_id, rules))
        job.start()
        jobs.append(job)
        line_idx += 1

    # wait for all started jobs
    for job in jobs:
        job.join()

    # write the collected classificatios to a file
    for device_id, (classification, line_idx) in devices_classifications.items():
        classifications_file.write(f"{line_idx},{device_id},{classification}\n")

def main():
    init_rules()

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
