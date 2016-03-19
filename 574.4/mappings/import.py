import idaapi
import idautils
import idc

def do_rename(l):
    splitted = l.split()
    straddr = splitted[0]
    strname = splitted[1].replace("\r", "").replace("\n", "")
    
    if straddr.find(":") != -1: #assuming form segment:offset
        #removing segment, offset should be unique, if it isn't so, we should handle it differently
        straddr = straddr.split(":")[1]
    
    eaaddr = int(straddr, 16)
    idc.MakeCode(eaaddr)
    idc.MakeFunction(eaaddr)
    idc.MakeNameEx(int(straddr, 16), strname, idc.SN_NOWARN)


if __name__ == "__main__":
    path = AskFile(0, "*", "Choose symbolize file.")
    f = open( path, "r")
    for l in f:
        do_rename(l)
    f.close()