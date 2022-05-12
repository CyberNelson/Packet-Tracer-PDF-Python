import pip,collections
from datetime import datetime
try:
    import pyshark
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

except:
    pip.main(["install","pyshark"])
    pip.main(["install","pandas"])
    pip.main(["install","matplotlib"])

    import pyshark
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
pd.set_option("display.max_rows",None,"display.max_columns",None)

class Reader:
    def __init__(self,packet_name="Processed Packet", packet_url="", packet_file_path="", packet_data=""):
        self.source=self.unpack(max(packet_url, packet_file_path, packet_data))
        self.data=self.extract(self.source)
        self.export(self.data,packet_name)
        

    def unpack(self, source):
        print("Unpacking Reference...\n")
        if isinstance(source, bytes):
            print("Source Type: Raw Data (bytes)\nSource Location: Direct Input\nSource Data:")
            print(source)
            return source
        elif isinstance(source, str) and "://" in source:
            print("Source Type: URL\nSource Location: "+source+"\nSource Data:")
            try:
                cap = pyshark.RemoteCapture(source)
                cap.sniff(timeout=50)
                print(''.join([str(cap[i]) for i in range(len(cap))]))
                return cap
            except:
                raise ReferenceError()
        else:
            print("Source Type: File\nSource Location: "+source+"\nSource Data:")
            try:
                cap = pyshark.FileCapture(source)
                if cap is None:
                    raise ReferenceError()
                else:
                    print(''.join([str(cap[i]) for i in range(len(cap))]))
                    return cap
            except:
                raise ReferenceError()
        return None

    def extract(self, data):
        print("Extracting Data...\n")
        layer_data={"Record ID":[],
                    "Packet Number":[],
                    "Packet Interface Captured":[],
                    "Packet Captured Length":[],
                    "Packet Total Length":[],
                    "Packet Sniff Timestamp":[],
                    "Packet Layer Name":[],
                    "Packet Layer Field":[],
                    "Packet Layer Value":[]}
        record_id=0
        for packet in data:
            packet_number=int(packet.number)
            print("Extracting Packet Number: "+str(packet_number))
            packet_meta=packet.__dict__
            layers=packet_meta["layers"]
            interface_captured=packet_meta['interface_captured']
            captured_length=int(packet_meta['captured_length'])
            total_length=int(packet_meta['length'])
            sniff_timestamp=datetime.fromtimestamp(float(packet_meta['sniff_timestamp']))
            layers=packet.__dict__["layers"]
            for layer in layers:
                fields=layer.field_names
                for field in fields:
                    if layer.get_field(field).showname_key is not None:
                        layer_data["Record ID"].append(record_id)
                        record_id+=1
                        layer_data["Packet Number"].append(packet_number)
                        layer_data["Packet Interface Captured"].append(interface_captured)
                        layer_data["Packet Captured Length"].append(captured_length)
                        layer_data["Packet Total Length"].append(total_length)
                        layer_data["Packet Sniff Timestamp"].append(sniff_timestamp)
                        layer_data["Packet Layer Name"].append(layer.layer_name)
                        layer_data["Packet Layer Field"].append(layer.get_field(field).showname_key)
                        value=list(str(layer.get_field(field).showname_value))
                        value_out=""
                        cut=1
                        for letter in value:
                            if cut==20:
                                value_out+="\n"+letter
                                cut=1
                            else:
                                value_out+=letter
                                cut+=1
                        layer_data["Packet Layer Value"].append(value_out)
        output=pd.DataFrame(layer_data)
        output=output.sort_values(["Packet Layer Field","Packet Sniff Timestamp","Packet Layer Name","Packet Number"])
        return output

    def export(self,data,name):
        print("Export Options:\n1) PDF (Still Resizing Text In PDF)\n2) Print Table")
        res=input("Answer (list number): ")
        if res is "1":
            print("Exporting Data To PDF File...")
            print("File Name: "+name+".pdf")
            print("Processing Data...")
            fig,ax=plt.subplots(figsize=(12,4))
            ax.axis('scaled')
            table=ax.table(cellText=data.values,colLabels=data.columns,loc='center')
            table.auto_set_font_size(False)
            table.set_fontsize(5)
            output=PdfPages(name+".pdf")
            output.savefig(fig,bbox_inches='tight')
            output.close()
            print("Export to PDF file finished")
        elif res is "2":
            while True:
                print("Fields To View:")
                for i in data["Packet Layer Field"].unique():
                    print(i)
                ans=input("Filter For: ")
                print(data[data["Packet Layer Field"]==ans])
                next_loop=input("Continue? (Y/N): ")
                if next_loop=="N":
                    break
        else:
            print("Cool story bro, roast some marshmallows and party s'more. You need a break.")
path=input("WireShark Packet Capture File Path: ")
file_name=input("File Name: ")
Reader(file_name,packet_file_path=path)
