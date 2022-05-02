import pandas as pd
import subprocess
import os

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
    df = pd.read_csv(csvFilename,sep='\t',header=0,names=fields)
    if not RetainCSV:
        os.remove(csvFilename)
    df.rename(columns = {'frame.number':'FrameNumber','frame.time':'Time','ip.src':'Source','ip.dst':'Destination','tcp.srcport':'TCP Source Port','tcp.dstport':'TCP Destination Port','udp.srcport':'UDP Source Port','udp.dstport':'UDP Destination Port','_ws.col.Protocol':'Protocol','frame.len':'Length','_ws.col.Info':'Info'},inplace = True)
    return df
    
attackFilename = './pcap_tftp_own_tool/level0/tftp_level0_13_seconds_attacker.pcapng'
attackerDf = pcapToDf(attackFilename)
attackerDf = attackerDf.loc[attackerDf['Protocol'].isin(["TFTP"])]
attackerBytesSent = attackerDf["Length"].sum()

victimFilename = './pcap_tftp_own_tool/level0/tftp_level0_13seconds_victim.pcapng'
victimDf = pcapToDf(victimFilename)
# look here: in victim pcap filter by destination port 50040 (the tftp servers source port). That will give you the tftp data transfers to the victim