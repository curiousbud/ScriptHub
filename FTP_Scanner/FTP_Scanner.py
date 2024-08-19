import ftplib

def anonLogin(hostname):
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous')
        print('\n [+] ' + str(hostname) + ' Anonymous FTP Login Succeeded.')
        ftp.quit()
        return True
    except:
        print('\n [-]' + str(hostname) + 'Anonymous FTP Login Failed.')    
        return False
        
        
if __name__ == '__main__':
 anonLogin(' 45.119.44.1 ')