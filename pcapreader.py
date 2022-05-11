import pandas as pd
import subprocess
import os
import ipaddress
from os.path import exists
from progressbar import Bar, ETA, \
    AdaptiveETA, Percentage, \
    ProgressBar 
class PcapReader:
    def __init__(self):
        self.widgets = [Percentage(),
                ' ', Bar(),
                ' ', ETA(),
                ' ', AdaptiveETA()]
    
    @staticmethod        
    def pcapToDf(filename,RetainCSV=False):
        """ Reads a pcap file with tshark, extracts the data in it and outputs it to a csv file.
            It then reads the csv file into a dataframe and deletes the csvFile

            Input: 
                Filename (string): path to pcap file
        """
        csvFilename = os.path.splitext(filename)[0] + '.csv'
        if not exists(csvFilename):
            command = "tshark -r " + filename + " -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E header=y -E separator=/t > " + csvFilename
            subprocess.run(command,shell=True)
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
        df.Source = df.Source.apply(lambda x: ipaddress.ip_address((x)))
        df.Destination = df.Destination.apply(lambda x: ipaddress.ip_address(x))
        df = df.astype({"TCP Source Port": 'Int64', "TCP Destination Port": 'Int64', "UDP Source Port": 'Int64', "UDP Destination Port":'Int64'})
        return df