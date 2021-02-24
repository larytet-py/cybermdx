# cymd

#include <string>
#include <sync>
/* SDK */

extern vector<string> getConnectdEndPoints(string serverHostNam) ;


struct NetworkMap 
{
    void add(string hostname);
    bool exists(string hostname);

    map<string, string> nodes;
    mutex m;
}

void NetworkMap::add(string hostname)
{
    mutex();
    nodes[hostname] = hostname;
}

bool exists(string hostname);
{
    mutex();
    return (allNodes.find(hostname) != allNodes.end())
}

static const MaxJobs = 100;
bool poolBusy(int jobsCount)
{
    return jobsCount > MaxJobs;
}


void crawler(NetworkMap &allNodes, strig hosname, int *jobCounter)
{
    auto hostnames =  getConnectdEndPoints(hosname);
    for hostname = range(hostnames) 
    {
        if (allNodes.exists(hostname))
        {
            continue;
        }
        // This is the new one
        allNodes.add(hostname);
        while (poolBusy(jobCounter))
        {
            chrono.sleep(10ms);
        } 
        atomic_inc(jobCounter);
        Thread.start(void []:
            crawler(hostname)),
            atomic_dec(jobCounter)
         };
    }
}

int main() 
{
    NetworkMap allNodes;
    int jobCounter;
    crawler(allNodes, serverHostname, &jobCounter)
    
}



/*

* relational data base (Idx=Mac) IP, MAC, VendorID, TypeID  /   (Idx VendorID) VendorName /   (Index ID) typeName
* engine lookup vendor by mac address
* engine fetch of known MAC address range
* Matching engine IP header
* Matching engine SSL handshake (encryption types, hostname, version)
* Traffic filter (hashtable) + listener (one or more IP flows from the same end point)

* Matching engine application layer (stream, deadline) -> type, probability, ok
   * rules engine drools/yara 

* Heristics
  - IP header
  - timing 
  - SSL handshake
  - TCP/IP payload

Heristic IP header
   * QoS
   * Protocol Type
   * 

*/



