import sys
import inspect
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

    # Get list of "Rule" classes
    module_classes = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    rules_classes = list(filter(lambda module_class: module_class[0].startswith("Rule"), module_classes))
    rules_classes = [rule_class[1] for rule_class in rules_classes]

    # Dictionary {rule_type: rule_class}
    rules_by_type = dict(zip(map(lambda rule_class: rule_class.type(), rules_classes), rules_classes)) 

    rules = []
    for fields_tuple in read_csv_line(rules_file):
        rule_id_s, rule_type, argument, classification = fields_tuple
        rule_id = int(rule_id_s)
        rule_class = rules_by_type[rule_type]
        rule = rule_class(rule_id, argument, classification)
        rules.append(rule)
        
    # sort by rule_id
    rules.sort(key=lambda rule: rule.rule_id)

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

def process_communication_job(device_id, device_queue, rules, devices_classifications):
    '''
    Read communications from the queue
    Apply all rules to the communication event for a specific device
    '''
    while True:
        (communication_event, line_idx) = device_queue.get()
        if line_idx < 1:  # end signal?
            break

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

def get_device_queue(devices_queues, device_id, rules, devices_classifications):
    '''
    If needed create a new queue, start a job, add both to the map devices_queues
    return the queue
    '''
    if not device_id in devices_queues:
        # I create a thread and a queue for every device ID
        queue = multiprocessing.Queue()
        job = threading.Thread(target=process_communication_job, args=(device_id, queue, rules, devices_classifications))
        devices_queues[device_id] = (queue, job)
        job.start()
    queue, _ = devices_queues[device_id]
    return queue

def process_communications(rules, communications_file, classifications_file):
    '''
    Read the file line by line
    Push every communication event to the corresponding queue. There is one queue for
    every device 
    The end result is devices_classifications map of classified devices 
    '''
    devices_classifications = {}
    devices_queues = {}  # For parallel execution I need a processing queue for every device_id

    line_idx = 1
    for fields_tuple in read_csv_line(communications_file):
        communication_event = csv_row_to_communication_event(fields_tuple)
        device_id = communication_event.device_id
        device_queue = get_device_queue(devices_queues, device_id, rules, devices_classifications)
        device_queue.put((communication_event, line_idx))
        line_idx += 1

    for _, (queue, job) in devices_queues.items():
        queue.put((None, 0))  # send 'end' signal to the queues
        job.join()            # wait for all started jobs to complete

    # write the collected classificatios to a file
    for device_id, (classification, line_idx) in devices_classifications.items():
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
