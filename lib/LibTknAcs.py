from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from pickle import loads, dumps
from getpass import getpass

from logging import getLogger
logger = getLogger('tknAcsLogger')

# Classes
class EncryptedConfig():
    """This class manages the configuration (with an encryption key to protect PSK secrecy).
    """

    def __new__(cls, fileName:str=None, key:bytes=None):
        """Tries to load fileName configuration file, or create an empty config.

        Args:
            fileName (str): Config path
            key (bytes, optional): Symmetric 32-bytes key. Defaults to None.

        Returns:
            EncryptedConfig: The created object
        """
        if key is not None:
            try:
                logger.debug(f'Opening & decryption of config file {fileName}')
                with open(file=fileName, mode="rb") as confFile:
                    encrypted = confFile.read()
                f = Fernet(key=urlsafe_b64encode(key))
                logger.debug(f'Decrypting...')
                decrypted = f.decrypt(encrypted)
                logger.debug(f'Loading object...')
                newObj = loads(decrypted)
                return newObj
            except FileNotFoundError:
                logger.info(f'{fileName} not find, generatig a new one.')
                return super().__new__(cls)
            except Exception as e:
                logger.error('Cannot open configuration.')
                logger.debug(e)
                raise e
        return super().__new__(cls)


    def __init__(self, fileName:str, key:bytes):
        """Initiates a configuration

        Args:
            key (bytes, optional): Symmetric 32-bytes key. Defaults to None.
        """
        if hasattr(self, '_filename'):
            for attribute in [
                "user",
                "_psk",
                "_counter",
                "host",
                "port",
                "password",
            ]:
                if not attribute in self.__dict__ :
                    logger.debug(f'Generating {attribute} attribute set to None by default.')
                    self.__setattr__(attribute, None)
            
            self.__setattr__('_fileName', fileName)
            self.__setattr__('_encKey', key)
            self._saveConfFile()


    def setConfig(self, **kwargs):
        """Sets an attribute value.
        """
        for kw in kwargs:
            logger.debug(f'Trying to change {kw}.')
            if kw == '_encKey':
                self.__setattr__(kw, passToKey(kwargs[kw]))
                self._saveConfFile()
            elif kw in self.__dict__.keys():
                self.__setattr__(kw, kwargs[kw])
                self._saveConfFile()
            else:
                logger.error(f'{kw} not existing in config.')
                print(f"No {kw} in config.")
    

    def getConfig(self, item):
        logger.debug(f'Accessing {item}.')
        return self.__getattribute__(item)


    def _saveConfFile(self):
        """Saves the configuration in encrypted configuration file defined in TKNACS_CLI_CONF

        Args:
            key (bytes): Symmetric 32-bytes key
        """
        try:
            logger.debug(f'Saving conf file to {self._fileName}.')
            decrypted = dumps(self)
            f = Fernet(key=urlsafe_b64encode(self._encKey))
            logger.debug(f'Encrypting...')
            encrypted = f.encrypt(bytes(decrypted))
            logger.debug(f'Saving file...')
            with open(file=self._fileName,mode="wb") as confFile:
                confFile.write(encrypted)
        except Exception as e:
            logger.error(f'Error while saving config.')
            logger.debug(e)
            raise e


class TknAcsApi():
    config=None
    
    def __init__(config):
        self.config = config




# Functions

def passToKey(passwd:str) -> bytes:
    """Converts a password to a 32-bytes key using sha256

    Args:
        passwd (str): A password

    Returns:
        bytes: SHA256-hashed password 
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passwd.encode())
    return digest.finalize()


def synchronize(config):
    """Synchronizes the client with server (counter)

    Args:
        config (EncryptedConfig): Loaded config file
    """
    print(f"synchro pour {config.user}")
    input()


def newPsk(config):
    logger.debug('NewPSK')
    pass


def changeConf(*args, **kwargs):
    config = kwargs.pop('config')
    item = args[0]
    display = f"New {item}"
    if 'reset' in args:
        asking = resetPass
    else:
        asking = input
        display = display + f"({config.getConfig(item)})"
    new = asking( display + ": " )
    print(f'Changing {item}' + ('' if "reset" in args else f' to {new}') + '.')
    config.setConfig(**{ item:new })
    

def resetPass(prompt: str='Enter password:') -> str:
    """Reset a password and returns the value (3 tries).

    Returns:
        str or None: Returns the password or None if bad password after 3 tries.
    """
    passwd1 = None
    passwd2 = None
    for i in range(3,0,-1):
        passwd1 = getpass(prompt=prompt)
        passwd2 = getpass("Retype it:")
        if passwd1 == passwd2 and isValidPass(passwd1):
            return passwd1
        else:
            print(f"[ERROR] Password are differents ({str(i-1)} trials remaining).")
    return ''
        

def isValidPass(passwd:str) -> bool:
    """Checks if a password is valid

    Args:
        passwd (str): the password

    Returns:
        bool: Password
    """
    return True
    

    
