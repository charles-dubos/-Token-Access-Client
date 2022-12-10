#!/usr/bin/env python3
#- *- coding:utf-8 -*-
"""This script is the client GUI for Token Access 
"""
__author__='Charles Dubos'
__license__='GNUv3'
__credits__='Charles Dubos'
__version__="0.1.0"
__maintainer__='Charles Dubos'
__email__='charles.dubos@telecom-paris.fr'
__status__='Development'


# Built-in
from getpass import getpass
from os.path import dirname, abspath
import logging.config


# Owned libs
from lib.LibTAClient import *
from lib.LibTAClientConnector import TknAcsConAPI, displayDict


# Module directives

## Creating specially-configured logger
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers':False,
    'formatters':{
        'default_formatter':{
            'format':'%(levelname)s:  %(asctime)s  [%(process)d][%(filename)s][%(funcName)s]  %(message)s',
        },
    },
    'handlers':{
        "file_handler":{
            'class':'logging.FileHandler',
            'filename':DEFAULT_CONFIG['local']['logging']['path'],
            'encoding':'utf-8',
            'formatter':'default_formatter',
        },
    },
    'loggers':{
        'tknAcsCli':{
            'handlers':['file_handler'],
            'level':DEFAULT_CONFIG['local']['logging']['level'],
            'propagate':True
        }
    }
})
logger = logging.getLogger('tknAcsCli')


# CLI menus

@menuHeader(menu="MAIN MENU")
def main_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the main menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """
    return menu(
        choices=[
            ("Local querying", client_query_menu, args, kwargs),
            ("Server-side querying", server_query_menu, args, kwargs),
            ("Configuration menu", conf_menu, args, kwargs),
        ],
        default=default,
        preamble="Hello {user}".format(
                user=kwargs['config'].getConfig('/local/user')
            ),
        postamble=kwargs['config'].checkConnect(),
        exit='Quit',
        *args,
        **kwargs,
    )


@menuHeader(menu="LOCAL QUERYING MENU")
def client_query_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the local querying menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """

    return menu(
        choices=[
            ("Check a given token", 
                kwargs['config'].isTokenInLocalWindow, (), {}),
            ("Change token window", 
                kwargs['config'].inputConfig, (), 
                {   passToKey:'hotp/window',
                    'entryType':int,
                    'connector':kwargs['connector']}
            ),
            ("Overwrite and regenerate PSK",
                kwargs['config'].generateNewPsk, (),
                {   "connector":kwargs['connector']}),
        ],
        default=default,
        preamble="What can I do for you, {user}?".format(
                user=kwargs['config'].getConfig('/local/user'),
            ),
        postamble=kwargs['config'].checkConnect(),
        *args,
        **kwargs,
    )
    

@menuHeader(menu="SERVER QUERYING MENU")
def server_query_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the server querying menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """

    return menu(
        choices=[
            ("Server counter synchronization", 
            kwargs['config'].synchronizeCounter, (),
                {'connector':kwargs['connector'],'interactive':'True'}
                ),
            ("Get attributed tokens for a user from server",
                connector.getTokenForUser, (),
                {'interactive':'True'}),
            ("Get all attributed tokens from server",
                connector.getAllTokens, (),
                {'interactive':'True'}),
        ],
        default=default,
        preamble="Last synchronization:{lastSync}".format(
                lastSync=kwargs['config'].getConfig('/hotp/lastSync')
            ),
        postamble=kwargs['config'].checkConnect(),
        *args,
        **kwargs,
    )
    

@menuHeader(menu="CONFIGURATION MENU")
def conf_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the local configuration menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """

    return menu(
        choices=[
            ("Change server host",
                kwargs['config'].inputConfig, (),
                {   'itemPath':'/server/host',
                    "connector":kwargs['connector']}),
            ("Change server port",
                kwargs['config'].inputConfig, (),
                {   'itemPath':'/server/port',
                    "connector":kwargs['connector']}),
            ("Pull configuration from server", 
                kwargs['config'].uploadFromServer, (), 
                {'connector':kwargs['connector']}),
            ("Overwrite and regenerate PSK",
                kwargs['config'].generateNewPsk, (),
                {"connector":kwargs['connector']}),
            ("Check server configuration & connection",
                kwargs['connector'].testConnection, (),
                {   'interactive':'True',
                    'config':kwargs['config']} ),
            ("Set manual configuration",man_conf_menu, args, kwargs),
        ],
        default=default,
        preamble="User Login:\t{user}\nPSK:\t{psk}\t\tLocal counter value:\t{counter}\nServer host:\t{host}\t\tServer port:\t{port}".format(
                user=kwargs['config'].getConfig('/local/user'),
                psk= 'OK' if kwargs['config'].getConfig('/hotp/psk') else 'NOT SET',
                counter=kwargs['config'].getConfig('/hotp/counter'),
                host=kwargs['config'].getConfig('/server/host'),
                port=kwargs['config'].getConfig('/server/port'),
            ),
        postamble=kwargs['config'].checkConnect(),
        *args,
        **kwargs,
    )
        
@menuHeader(menu="MANUAL CONFIGURATION")
def man_conf_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the manual configuration menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """

    return menu(
        choices=[
            ("Change local configuration file password",
                kwargs['config'].inputConfig, ("reset"),
                {   'itemPath':'_password',}),
            ("Change user email address:", 
                kwargs['config'].inputConfig, (), 
                {   'itemPath':'/local/user'}),
            ("Set token window", 
                kwargs['config'].inputConfig, (), 
                {   'itemPath':'/hotp/window',
                    'entryType':int,
                }),
            ("Set logging path",
                kwargs['config'].inputConfig, (), 
                {   'itemPath':'/local/logging/path'}),
            ("Set logging level",
                kwargs['config'].inputConfig, (), 
                {   'itemPath':'/local/logging/level',
                    'inputList':['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                }),
            ("Print all decrypted configuration",
                displayDict, (),
                {'dico': kwargs['config'].getConfig(itemPath='_configuration'),
                'confidential': ['psk'],
                }),
        ],
        default=default,
        preamble="User Login:\t{user}\nPSK:\t{psk}\nLocal counter value:\t{counter}".format(
                user=kwargs['config'].getConfig('/local/user'),
                psk= 'OK' if kwargs['config'].getConfig('/hotp/psk') else 'NOT SET',
                counter=kwargs['config'].getConfig('/hotp/counter'),
            ),
        postamble=kwargs['config'].checkConnect(),
        *args,
        **kwargs,
    )


# Launcher
if __name__=="__main__":
    
    config = configLoader(DEFAULT_CONFIG_FILE)
    # Creating API connector
    connector = TknAcsConAPI(
        username=config.getConfig('/local/user'),
    )
    connector.update(config)

    # Main menu
    main_menu(
        config=config,
        connector=connector,
    )
