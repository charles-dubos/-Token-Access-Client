#!/usr/bin/env python3
#- *- coding:utf-8 -*-
"""This module contains functionalities for Token Access 
"""
__author__='Charles Dubos'
__license__='GNUv3'
__credits__='Charles Dubos'
__version__="0.1.1"
__maintainer__='Charles Dubos'
__email__='charles.dubos@telecom-paris.fr'
__status__='Development'


# Built-in
from base64 import urlsafe_b64encode
from pickle import loads, dumps
from getpass import getpass
from datetime import datetime
from logging import getLogger
from os.path import exists
import json

# Other libs
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes


# Owned libs
from lib.LibTACrypto import *


# Module directives

## Constants
DEFAULT_CONFIG_FILE="TknAcsClient.conf"
API_CERT_NAME='TknAcsAPI.pem'

DEFAULT_CONFIG={
    'local':{
        'logging':{
            'path':'./TknAcsClient.log',
            'level':'DEBUG',
        }
    }

}

## Load logger
logger = getLogger('tknAcsCli')


# Classes

## Class to manage encrypted local configuration
class EncryptedConfig():
    """This class manages the configuration (with an encryption key to protect
    PSK secrecy).
    
    !Only '_configuration' attribute is saved!
    """


    def __init__(
        self,
        filename:str,
        password:str):
        """Initiates a configuration from the filename and user password

        Args:
            filename (str): Filename
            password (str): Local password.
        """
        self._filename=filename
        self._password=password
        self._configuration=DEFAULT_CONFIG

        if exists(self._filename):
            self._loadConfFile()
    

    def _loadConfFile(self):
        """Loads an encrypted file with pre-configured key.

        Raises:
            e: Error in opening process.
        """
        try:
            logger.info(f'Reading & loading {self._filename}')
            with open(file=self._filename, mode="rb") as confFile:
                encrypted = confFile.read()
            logger.debug('Loading encryption key')
            f = Fernet(
                key=passToKey(self.getConfig(itemPath='_password'))
            )
            logger.debug('Decrypting data')
            decrypted = f.decrypt(encrypted)
            logger.debug('Loading object')
            newObj = loads(decrypted)
            self.setConfig(
                '_configuration',
                value=newObj,
                saveToFile=False
            )
            self.reloadLogger()
        except Exception as e:
            logger.error(f'Cannot open configuration: {repr(e)}')
            raise e


    def _saveConfFile(self):
        """Saves the configuration in encrypted configuration file defined
        in TKNACS_CLI_CONF local constant.

        Args:
            password (str): Local password.
        """
        assert self.getConfig(itemPath='/local/user'),\
            'Cannot save to file if user is undefined'
        
        try:
            logger.info(f'Saving configuration dict to {self._filename}.')
            decrypted = dumps(self.getConfig(itemPath='_configuration'))
            logger.debug('Loading encryption key')
            f = Fernet(
                key=passToKey(self.getConfig(itemPath='_password'))
            )
            logger.debug('Encrypting data')
            encrypted = f.encrypt(bytes(decrypted))
            logger.debug(f'Saving to {self._filename}')
            with open(file=self._filename,mode="wb") as confFile:
                confFile.write(encrypted)
        except Exception as e:
            logger.error(f'Error while saving configuration: {repr(e)}')
            raise e


    def getConfig(
        self,
        itemPath:str,
        sep='/',
        interactive=False):
        """A function to access a dictionnary configuration element.
        Returning an empty dict if not found.

        Args:
            data (dict): the dictionnary to seek
            path (str): the path to dict key
            sep (str, optional): The path separator. Defaults to '/'.
            interactive (bool, optional): Console return. Defaults to False.

        Returns:
            any: content of dict at this path
        """
        logger.debug(f'Accessing {itemPath}.')

        if itemPath in self.__dict__:
            logger.debug('Non-recordable configuration identified.')
            if interactive:
                input(str(self.__getattribute__(itemPath)))
            return self.__getattribute__(itemPath)
        
        assert itemPath[0] == '/', 'Bad formatted itemPath'
        pathList = [ item for item in itemPath.split(sep=sep) if item != ""]
        data = self._configuration

        for item in pathList:
            if item in data:
                logger.debug(f'Entering in {item}')
                data=data[item]
            else:
                logger.debug(f'{item} not found')
                return {}
        logger.debug(f'Data found: returning it')
        if interactive:
            input(str(data))
        return data


    def setConfig(
        self,
        itemPath:str,
        sep='/', 
        value=None, 
        saveToFile=True):
        """Sets a configuration element (default to None).
        Creates the path if not exists.
        Path not starting with / references not recorded config.

        Args:
            path (str): the path to configuration key
            sep (str, optional): The path separator. Defaults to '/'.
            value (any): content to set at this path. Default to None
            saveToFile (bool): saves the configuration file. Default to True
        """
        logger.info(f'Changing configuration of {itemPath}')

        if itemPath in self.__dict__:
            logger.debug('Non-recordable configuration identified & set.')
            self.__setattr__(itemPath, value)
            return 

        assert itemPath[0] == '/', 'Bad formatted itemPath'
        pathList = [ item for item in itemPath.split(sep=sep) if item != ""]
        data = self._configuration

        for item in pathList[:-1]:
            if not item in data:
                logger.debug(f'{item} not existing in path: initializing it')
                data[item]={}
            logger.debug(f'Entering in {item}')
            data=data[item]
        data[pathList[-1]]=value
        logger.debug(f'Data set')

        if saveToFile:
            self._saveConfFile()
    

    def setManyConfig(
        self,
        dictOfConfigs:dict):
        """Sets many config from dict.
        The dict must be formatted with keys as itemPath and their values as 
        values.

        Args:
            dicOfConfigs (dict): Dict of configurations
        """
        for configPath in dictOfConfigs:
            self.setConfig(
                itemPath=configPath,
                value=dictOfConfigs[configPath],
                saveToFile=False
            )
        self._saveConfFile()


    def inputConfig(
        self, 
        itemPath:str, 
        entryType:type=str, 
        inputList:list=[],
        *args, **kwargs):
        """An interactive display for configuration change.
        If 'reset' in args, the input is set to password input (no displaying).

        Args:
            itemPath (str): path to configuration item
            entryType (type, optional): input entry type. Defaults to str.
            inputList (type, optional): Allowed entries. Ignored if not given.
        """
        display = f"New {itemPath}"

        if 'reset' in args:
            asking = resetPass
        else:
            asking = input
            display = display + f"({str(self.getConfig(itemPath=itemPath))})"

        # Displaying list if present
        for index, item in enumerate(inputList):
            print(' {index}: {item}'.format(
                index=index,
                item=item,
            ))
        new = asking( display + ": " )

        # Setting value in list if present
        if len(inputList) != 0:
            try:
                new=inputList[int(new)]
            except:
                new=''
        
        if new == '' and not 'reset' in args:
            logger.debug(f'Reseting {itemPath} to None')
            print(f'Reseting {itemPath} to None.')
            self.setConfig(
                itemPath=itemPath,
                value=None,
            )
        else:
            logger.debug(f'Setting {itemPath}')
            print(f'Setting {itemPath}')
            self.setConfig(
                itemPath=itemPath,
                value=(entryType)(new),
            )

        if 'connector' in kwargs:
            kwargs['connector'].update(config=self)


    def checkConnect(self):
        """Checks if connection configuration exists.

        Returns:
            str: The response message.
        """
        if not self.getConfig('/server/host'):
            return 'NO SERVER CONFIGURED: Please set and check server configuration.\n'
        elif not self.getConfig('/hotp/psk'):
            return 'NO PSK SET: please set a PSK to use this service.\n'
        else:
            return ''


    def synchronizeCounter(
        self, 
        connector, 
        interactive=False):
        """Synchronizes the local counter with the server.

        Args:
            connector (TknAcsConnector): A configured connector
            interactive (bool, optional): Interactive return. Defaults to False.
        """
        logger.debug(f"Synchronizing {self.getConfig('/local/user')}...")
        serverCounter = connector.getCount()
        lastSync= datetime.now().strftime('%Y/%m/%d@%H:%M')

        logger.debug('Saving counter to configuration file')
        self.setManyConfig({
            '/hotp/counter':serverCounter,
            '/hotp/lastSync':lastSync,
        })

        if interactive:
            input('Counter synchronization done.')


    def isTokenInLocalWindow(
        self,
        token:bytes=None,
        **ellipticContext)-> bool:
        """Checks if a token is one of the token in local window.
        If no token given asks for one and displays the result.

        Args:
            token (bytes, optional): A token in bytes format. Defaults to None.

        Returns:
            bool: result of test
        """

        interactive = True if token is None else False
        
        hotpConf = self.getConfig('/hotp')

        if not hotpConf['psk']:
            print('Please generate a PSK and set a window.')
            logger.debug('window, counter or PSK not set.')
            return False
        
        begin=max(0, hotpConf['counter'] - hotpConf['window'])
        end=hotpConf['counter'] + hotpConf['window']
        if interactive:
            token = input('Token to check:').encode()

        for count in range(begin, end):
            hotp = getHotp(
                preSharedKey=hotpConf['psk'],
                count=hotpConf['counter'],
                **ellipticContext,
            )
            if hotp == token:
                if interactive:
                    input('[OK] Found {token} for counter {count}'.format(
                        token=token.decode(),
                        count=count,
                    ))
                return True
        if interactive:
            input('[ERROR] No {token} found between {begin} and {end}'.format(
                token=token.decode(),
                begin=begin,
                end=end,
            ))
        return False


    def generateNewPsk(
        self,
        connector,
        interactive=True):
        """This method creates a new PSK from server and saves it to
        configuration.

        Args:
            connector (TknAcsConnector): A network-configured connector
        """
        if interactive:
            if input('This will reset the server PSK:\n'
                'ALL PENDING MESSAGES WILL BE LOST!\n'
                'Type \'yes\' to confirm:') != 'yes':
                return False
        logger.debug('Generating a new PSK...')
        psk, serverCounter = connector.setNewPsk(
            **self.getConfig('/context/elliptic'),
            **self.getConfig('/context/hash'),
            )
        lastSync= datetime.now().strftime('%Y/%m/%d@%H:%M')

        self.setManyConfig({
            '/hotp/psk':psk,
            '/hotp/counter':serverCounter,
            '/hotp/lastSync':lastSync,
        })

    
    def reloadLogger(self):
        """Reloads the logger filename and level
        """
        level=self.getConfig(itemPath='/local/logging/level')
        filename=self.getConfig(itemPath='/local/logging/path')
        logger.handlers[0].setLevel(level=level)
        logger.debug(f'Logging level set to {level}')
        logger.handlers[0].filename=filename
        logger.debug(f'Logging path set to {filename}')


    def uploadFromServer(
        self,
        connector,
        interactive=False):
        """Upload configuration from server

        Args:
            connector (TknAcsConnector): The connector
            interactive (bool, optional): _description_. Defaults to False.
        """
        logger.info('Uploading server cert and general config')
        generalConfig = connector.uploadConfig()
        logger.debug('General config: {}'.format(str(generalConfig)))

        self.setManyConfig({
            '/hotp/window':generalConfig['window'],
            '/context':generalConfig['context'],
            '/server/cert':connector.cert,
        })

        logger.debug('Updating PSK')
        if self.getConfig(itemPath='/hotp/psk'):
            self.synchronizeCounter(connector)
        else:
            self.generateNewPsk(connector, interactive=False)


# Functions

## Configuration loader
def configLoader(filename:str) -> EncryptedConfig:
    """This file loads an encrypted configuration form a filename:
    - Ask for the key if file exists
    - Ask for a key and create a new one if not exists

    Args:
        filename (str): encrypted configuration file path

    Returns:
        EncryptedConfig: The populated EncryptedConfiguration object
    """

    if not exists(filename):
        logger.info("Configuration file not find, initializing a new one...")
        user = input("User email address: ")
        passwd = resetPass("Local password")
        if passwd is None:
            raise InvalidToken('Password needed for the configuration file.')

        config = EncryptedConfig(
            filename=filename,
            password=passwd,
        )
        config.setConfig(itemPath='/local/user', value=user)
        logger.info("Configuration created.")

    else:
        for chance in range(3,0,-1):
            try:
                logger.debug(f'Password asked {str(chance)} remaining')
                passwd = getpass('Encryption password'
                    f'({str(chance)} tests remaining): ')
                config = EncryptedConfig(
                    filename=filename,
                    password=passwd,
                )
                logger.info("Configuration loaded.")
                break
            except KeyboardInterrupt:
                passwd = None
                break
            except:
                passwd = None
        if passwd is None:
            logger.critical('Bad password, exiting.')
            raise InvalidToken('Bad password, cannot decrypt config.')
    
    return config


# Password management functions

def passToKey(password:str, **hashContext) -> bytes:
    """Converts a password to its base64-urlsafe 32-bits hashed key

    Args:
        password (str): A password

    Returns:
        bytes: hashed password 
    """
    hashing = HashText(plaintext=password,**hashContext)
    return base64.urlsafe_b64encode(hashing.getHash()[:32])


def resetPass(prompt: str='Enter password') -> str:
    """Reset a password and returns the value (3 tries).

    Returns:
        str or None: Returns the password or None if bad password after 3 tries.
    """
    passwd1 = None
    passwd2 = None
    for i in range(3,0,-1):
        passwd1 = getpass(prompt=prompt+': ')
        passwd2 = getpass("Retype it: ")
        if passwd1 == passwd2 and isValidPass(passwd1):
            return passwd1
        else:
            print('[ERROR] Password are differents'
                f'({str(i-1)} trials remaining).')
    return ''
        

def isValidPass(passwd:str) -> bool:
    """Checks if a password is valid
    TODO: Not implemented

    Args:
        passwd (str): the password

    Returns:
        bool: Password
    """
    return True
    

# Display functions

def menuHeader(menu:str):
    """Decorator for menus

    Args:
        menu (str): Name displayed for the menu
    """
    def menuDecorator(func):
        def header(*args, **kwargs):
            logger.info(f"Displaying {menu}")
            res=1
            while res !=0:
                print('\n\n',
                    ''.join(['=' for i in range(50)]),
                    f"TOKEN ACCESS CLIENT - {menu}",
                    ''.join(['-' for i in range(50)]),
                sep='\n')
                res = func(default=res,*args, **kwargs)
            return res
        return header
    return menuDecorator


def menu(
    choices:list,
    default:int=0,
    preamble='',
    postamble='',
    exit:str='Return',
    *args, **kwargs):
    """Common part for menus

    Args:
        choices (list): List of tuples
            (display:str, command:function, args:tuple, kwargs:dict)
        default (int, optional): Default position of selector. Defaults to 0.
        preamble (str, optional): String to print before menu. Defaults to ''.
        postamble (str, optional): String to print after menu. Defaults to ''.
        exit (str, optional): Display for this menu end. Defaults to 'Return'.

    Returns:
        int: Selected choice in menu
    """
    
    print(preamble)
    for i,choice in enumerate(choices,start=1):
        print(f"{'>' if i == default else ' '} {str(i)}: {choice[0]}")

    print(f"{'>' if default ==0 else ' '} 0: {exit}")
    print(postamble)

    try:
        default = int(input(f"\nChoice (default to {str(default)}): "))
    except:
        pass

    if default != 0:
        try:
            choices[default-1][1](
                *(choices[default-1][2]),
                **(choices[default-1][3]),
            )
        except Exception as e:
            logger.debug(f'"{repr(e)}" occured in menu!')
            print('Error "{err}" occured when executing [{func}]'.format(
                err=str(e),
                func=choices[default-1][1].__name__
            ))
    
    return default
