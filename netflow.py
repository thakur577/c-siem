# had to install pyshark
# using Python 2.7.12
class pysharkSniffer():
    import pyshark
    out_string = ""
    i = 1

    cap = pyshark.LiveCapture(interface='TP-LINK Gigabit Ethernet USB Adapter')

    cap.sniff(packet_count=5)

    for pkt in cap:

        out_file = open("Eavesdrop_Data.txt", "w")
        out_string += "Packet #         " + str(i)
        out_string += "\n"
        out_string += str(pkt)
        out_string += "\n"
        out_file.write(out_string)
        i = i + 1
    cap.close()