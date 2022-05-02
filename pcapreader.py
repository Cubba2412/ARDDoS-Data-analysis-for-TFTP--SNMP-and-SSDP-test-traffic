from numpy import datetime64
import pandas as pd
import subprocess
import os
from cyberpandas import to_ipaddress
from alive_progress import alive_it # For printing of progress in for loops

def pcapToDf(filename,RetainCSV=False):
    """ Reads a pcap file with tshark, extracts the data in it and outputs it to a csv file.
        It then reads the csv file into a dataframe and deletes the csvFile

        Input: 
            Filename (string): path to pcap file
    """
    csvFilename = os.path.splitext(filename)[0] + '.csv'
    with open(csvFilename,'w') as f:
        command = "tshark -r " + filename + " -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E header=y -E separator=/t"
        subprocess.run(command.split(), stdout =f)
    # Read headers
    fields = pd.read_csv(csvFilename, index_col=0, nrows=0).columns.tolist()[0].split('\t')
    df = pd.read_csv(csvFilename,sep='\t',header=0,names=fields,na_values=['None'])
    if not RetainCSV:
        os.remove(csvFilename)
    df.rename(columns = {'frame.number':'FrameNumber','frame.time':'Time','ip.src':'Source','ip.dst':'Destination','tcp.srcport':'TCP Source Port','tcp.dstport':'TCP Destination Port','udp.srcport':'UDP Source Port','udp.dstport':'UDP Destination Port','_ws.col.Protocol':'Protocol','frame.len':'Length','_ws.col.Info':'Info'},inplace = True)
    # Conver time column to correct format
    df.Time = df.Time.apply(lambda x: x.strip(" CEST"))
    df.Time = pd.to_datetime(df["Time"], format='%b %d, %Y %H:%M:%S.%f')
    df.Source = df.Source.fillna('0.0.0.0') # 0.0.0.0 is used to represent missing data (In the case of ARP packets for example)
    df.Destination = df.Destination.fillna('0.0.0.0') # 0.0.0.0 is used to represent missing data (In the case of ARP packets for example)
    df.Source = df.Source.apply(lambda x: to_ipaddress(x))
    df.Destination = df.Destination.apply(lambda x: to_ipaddress(x))
    df = df.astype({"TCP Source Port": 'Int64', "TCP Destination Port": 'Int64', "UDP Source Port": 'Int64', "UDP Destination Port":'Int64'})
    return df

## Get All pcap filenames:
victimFilenames = []
attackerFilenames = []
for root, dirs, files in os.walk("./"):
    for file in files:
        if file.endswith(".pcapng"):
            if "victim" in file:
                victimFilenames.append(os.path.join(root, file))
            if "attacker" in file:
                attackerFilenames.append(os.path.join(root, file))



## Get attacker bytes sent
attackerBytes = []
for attackFile in alive_it(attackerFilenames):
    # Get attack level
    start = attackFile.find('level')
    end = start+len('level')+1
    level = attackFile[start:end]
    attackerDf = pcapToDf(attackFile)
    # By finding the TFTP packets and summing the byte lengths we get the total number of bytes send by the attacker
    attackerDf = attackerDf.loc[attackerDf['Protocol'].isin(["TFTP"])]
    attackerBytesSent = attackerDf["Length"].sum()
    attackerBytes.append({'Level':level,'Attacker Bytes Sent':attackerBytesSent})

attackerBytes = pd.DataFrame(attackerBytes).sort_values('Level')

victimBytes = []
for victimFile in alive_it(victimFilenames):
    # Get attack level
    start = victimFile.find('level')
    end = start+len('level')+1
    level = victimFile[start:end]
    victimDf = pcapToDf(victimFile)
    # In the victim pcap filtering by destination port 50040 (the tftp servers source port) gives the tftp data transfered to the victim
    victimBytesReceived = victimDf.loc[(victimDf['Protocol'] == "UDP") & (victimDf['UDP Destination Port'] == 50040)]["Length"].sum()
    victimBytes.append({'Level':level,'Victim Bytes Received':victimBytesReceived})
victimBytes = pd.DataFrame(victimBytes).sort_values('Level')

print(attackerBytes)
print(victimBytes)
