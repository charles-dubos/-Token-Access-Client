#!/usr/bin/env python3
#- *- coding:utf-8 -*-
"""This module contains functionalities for Token Access 
"""
__author__='Charles Dubos'
__license__='GNUv3'
__credits__='Charles Dubos'
__version__="0.1.0"
__maintainer__='Charles Dubos'
__email__='charles.dubos@telecom-paris.fr'
__status__='Development'


# Built-in
from ssl import get_server_certificate
from logging import getLogger
from abc import ABC, abstractmethod


# Other libs
from requests import get, post


# Owned libs
from lib.LibTACrypto import PreSharedKey
from lib.LibTAClient import API_CERT_NAME


# Module directives

## Load logger
logger = getLogger('tknAcsClient')


# Classes

class TknAcsConnector(ABC):
    conType=None
    username=None

    @abstractmethod
    def getTokenForUser(self,recipient, interactive=False)->dict:
        pass

    @abstractmethod
    def getAllTokens(self, interactive=False)->dict:
        pass

    @abstractmethod
    def getCount(self, interactive=False)->int or None:
        pass

    @abstractmethod
    def setNewPsk(self,publicKey) -> bytes:
        pass

    @abstractmethod
    def update(self,config):
        pass
    
    @abstractmethod
    def testConnection(self):
        pass


class TknAcsConAPI(TknAcsConnector):
    conType="API"
    host=None
    port=None
    cert=False
    

    def __init__(
        self,
        username:str,
        host:str=None,
        port:str=None,
        cert:str=False):
        """Initiates the connector

        Args:
            username (str): user email address
            host (str, optional): The server host. Defaults to None.
            port (str, optional): The server port. Defaults to None.
            cert (str, optional): The server SSL cert. Defaults to False.
        """
        logger.debug(f'creating connector to {host}:{port} for {username}')
        self._load(
            host=host,
            username=username,
            port=port,
            cert=cert,
        )


    def update(self, config):
        """Changes the connector configuration with the given file

        Args:
            config (EncryptedConfig): A configuration object
        """
        self._load(
            username=config.getConfig('/local/user'),
            host=config.getConfig('/server/host'),
            port=config.getConfig('/server/port'),
            cert=False if not config.getConfig('/server/cert')
                else config.getConfig('/server/cert'),
        )


    def _load(
        self,
        username:str=None,
        host:str=None,
        port:str=None,
        cert:str=False):
        if host is not None:
            logger.debug(f'New connector host: {host}')
            self.host = host
        if port is not None:
            logger.debug(f'New connector port: {port}')
            self.port = port
        if username is not None:
            logger.debug(f'New connector username: {username}')
            self.username = username
        if cert:
            logger.debug(f'New connector server certificate: {cert}')
            self.cert = cert

    
    def apiUrl(self)->str:
        """Generates URL for API server

        Returns:
            str: The URL string
        """
        assert self.host is not None, 'Cannot crate url from None host.'
        return 'http{ssl}://{host}:{port}/'.format(
            ssl = 's' if self.cert else '',
            host = self.host,
            port = self.port,
        )


    def userUrl(self)->str:
        """Generates URL for user access in API server

        Returns:
            str: The user URL API point
        """
        return '{api_url}{username}/'.format(
            api_url=self.apiUrl(),
            username=self.username,
        )

    
    def setNewPsk(self, **kwargs)->bytes:
        """Generates the PSK with the server based on ECDH

        Returns:
            bytes: the bytes-PSK
        """
        pskBase = PreSharedKey(**kwargs)

        logger.debug(f"Generated pubKey: {pskBase.exportPubKey()}")

        logger.debug(f'Calling {self.userUrl() + "generateHotpSeed"}')
        response = post(
            url=self.userUrl() + 'generateHotpSeed',
            data = {
                'pubKey':pskBase.exportPubKey(),
            },
            verify=self.cert,
        )
        print(response.request.body)
        psk = pskBase.generate(
            user=response.json()['user'],
            recipientPubKey=response.json()['pubKey'],
        )
        counter = response.json()['counter']
        return (psk, counter)


    def getCount(self)->int or None:
        """Requests the counter value at the server

        Returns:
            int or None: Counter value
        """
        logger.debug(f'Calling {self.userUrl() + "getCount"}')
        response = get(
            url=self.userUrl() + 'getCount',
            verify=self.cert,
        )
        return response.json()['counter']


    def getAllTokens(self, interactive=False)->dict:
        """Requests all pending token at the server

        Args:
            interactive (bool, optional): Interactive mode. Defaults to False.

        Returns:
            dict: returns the token and their sender.
        """
        logger.debug(f'Calling {self.userUrl() + "getAllTokens"}')
        response = get(
            url=self.userUrl() + 'getAllTokens',
            verify=self.cert,
        )
        logger.debug(f'{response.content}')
        if interactive:
            displayDict(
                dico=response.json()['tokens'],
                emptyMsg='No token available'
            )
        return response.json()['tokens']


    def getTokenForUser(
        self,
        sender:str=None,
        interactive=False)->dict:
        """Requests only the tokens sent by a specified user

        Args:
            sender (str): sender email.
            interactive (bool, optional): Interactive mode. Defaults to False.

        Returns:
            dict: returns the tokens and their sender
        """
        if sender is None:
            if interactive:
                sender = input("Enter sender name:")
            else:
                raise ValueError('sender cannot be set to None if not interactive')
        response = get(
            url=self.apiUrl() + "/" + self.username + '/getAllTokens',
            params = {
                'recipient':self.recipient,
            })
        if interactive:
            displayDict(
                dico=response.json()['tokens'],
                emptyMsg='No token available'
            )
        return response.json()['tokens']


    def testConnection(self, config=None, interactive=False)->bool:
        """Tests the connection and synchronizes the counter.
        Initiates the PSK if None.

        Args:
            interactive (bool, optional): Interactive mode. Defaults to False.

        Returns:
            bool: Connection state
        """
        url = None
        try:
            logger.info('Connection tests:')
            if interactive:
                print("Connection tests:", end='\t')
            for url in [
                self.apiUrl(),
                self.apiUrl() + self.username
            ]:
                if interactive:
                    print('\nTesting connection to {url}'.format(url=url), end='\t')
                response = get(
                    url=url,
                    verify=self.cert,
                )
                logger.debug(response.json())
                assert response.status_code ==200, 'Status is not 200.'
                if interactive:
                    print('[OK]', end='\n')
                
            if interactive:
                input()

        except Exception as e:
            logger.warning('Test Failed: '+ repr(e))
            if interactive:
                input('[Failed]\nThe following error occured: {error}\nURL: {url}'.format(
                    error=repr(e),
                    url=url,
                    )
                )
            return False
            
        return True


    def uploadConfig(self, interactive=False)->dict:
        """Uploads certificate & default configuration from server API

        Args:
            interactive (bool, optional): Displays results. Defaults to False.

        Returns:
            dict: containing the default configurations
        """

        ## Load cert from server
        logger.info('Collecting certificate from server')
        cert = get_server_certificate((self.host,self.port))
        logger.debug(f'Saving certificate to {API_CERT_NAME}')
        with open(file=API_CERT_NAME, mode='w') as fd:
            fd.write(cert)
        logger.debug(f'Referring to {API_CERT_NAME}')
        self.cert = API_CERT_NAME
        if interactive:
            print(f'Server certificate downloaded in {API_CERT_NAME}')

        logger.debug(f'Calling {self.userUrl() + "getConfiguration"}')
        response = get(
            url=self.userUrl() + 'getConfiguration',
            verify=self.cert,
        )

        if interactive:
            print(response.json())
        return response.json()


    
# Functions

def displayDict(
    dico:dict,
    emptyMsg:str='Dictionnary is empty',
    level:int=0,
    confidential:list=[],
    ):
    """Displays a dictionnary 

    Args:
        dico (dict): _description_
        emptyMsg (str, optional): _description_. Defaults to 'Dictionnary is empty'.
        level (int, optional): _description_. Defaults to 0.
        confidential (list, optionnal): List of keys not to display.
    """
    tabulate=''.join('\t' for _ in range(level))
    if len(dico)==0:
        print(tabulate + emptyMsg)
    else:
        for key in dico:
            print(tabulate + f'{key}: ', end='')
            if key in confidential:
                print( '*' if dico[key] else 'None')
            elif isinstance(dico[key], dict):
                print()
                displayDict(
                    dico=dico[key],
                    emptyMsg=emptyMsg,
                    level=level+1,
                    confidential=confidential,
                )
            else:
                print(str(dico[key]))
    if level==0:
        input()

