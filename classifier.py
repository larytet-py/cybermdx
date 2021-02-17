'''
Get two iput CSV files rules and commuincaitons
Produce classifications for every line in the communication file 
'''

from collections import namedtuple

Communication = namedtuple('Communication', ["id", "timestamp", "device_id", "protocol_name", "host"])

class RuleCommunicatingProtocol():
    def __init__(self, id, protocol_name):
        self.id, self.protocol_name = id, protocol_name
        
    def match(communication):
        return communication.protocol_name == self.protocol_name
        


def loadRules():
    def __init__(self, id, ):


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




