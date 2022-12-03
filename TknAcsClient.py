from getpass import getpass
from os.path import dirname, abspath, exists

from lib.LibTknAcs import *

import logging.config
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers':False,
    'formatters':{
        'default_formatter':{
            'format':'%(levelname)s:%(asctime)s\t%(message)s',
        },
    },
    'handlers':{
        "file_handler":{
            'class':'logging.FileHandler',
            'filename':dirname(abspath(__file__)) + '/TknAcsCli.log',
            'encoding':'utf-8',
            'formatter':'default_formatter',
        },
    },
    'loggers':{
        'tknAcsLogger':{
            'handlers':['file_handler'],
            'level':'DEBUG',
            'propagate':True
        }
    }
})
logger = logging.getLogger('tknAcsLogger')

TKNACS_CLI_CONF = dirname(abspath(__file__)) + "/TknAcsClient.conf"


# CLI menus
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


def menu(choices:list, default:int=0, preamble='', postamble='', exit:str='Return', *args, **kwargs):
    """Common part for menus

    Args:
        choices (list): List of tuples(display:str, command:function, args:tuple, kwargs:dict)
        default (int, optional): Default position of selector. Defaults to 0.
        preamble (str, optional): String to print before menu. Defaults to ''.
        postamble (str, optional): String to print after menu. Defaults to ''.
        exit (str, optional): Display for this menu end. Defaults to 'Return'.

    Returns:
        _type_: _description_
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
        choices[default-1][1](
            *(choices[default-1][2]),
            **(choices[default-1][3]),
        )
    
    return default


@menuHeader(menu="MAIN MENU")
def main_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the configuration menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """
    return menu(
        choices=[
            ("Server synchronization", synchronize, (), kwargs),
            ("Get attributed tokens from server", print, ("TODO",), {}),
            ("Configure", conf_menu, args, kwargs),
        ],
        default=default,
        preamble=f"Hello {(kwargs['config']).user}\n",
        exit='Quit',
        *args,
        **kwargs,
    )
    

@menuHeader(menu="CONFIGURATION MENU")
def conf_menu(default:int=0, *args, **kwargs) -> int:
    """Displays & execute the main menu

    Args:
        default (int, optional): Initial selection. Defaults to 0.

    Returns:
        int: Selected item index
    """

    return menu(
        choices=[
            ("Change user email address:", changeConf, ("user",), {"config":kwargs['config']}),
            ("Change server password:", changeConf, ("password","reset"), {"config":kwargs['config']}),
            ("Change server host", changeConf, ("host",), {"config":kwargs['config']}),
            ("Change server port", changeConf, ("port",), {"config":kwargs['config']}),
            ("Change file password", changeConf, ("_encKey","reset"), {"config":kwargs['config']}),
            ("Overwrite and regenerate PSK", newPsk, (), kwargs)
        ],
        default=default,
        preamble=f"""\
User creds:\tLogin: {(kwargs['config']).user}\tPass: {"OK" if (kwargs['config']).password is not None else "NOK"}
Server host:\t{(kwargs['config']).host}
Server port:\t{(kwargs['config']).port}
""",
        *args,
        **kwargs,
    )
    

# Main part
if __name__=="__main__":

    # Loading or generating secret configuration
    if not exists(TKNACS_CLI_CONF):
        logger.info("Configuration file not find, initializing a new one...")
        user = input("User email address: ")
        passwd = resetPass("Local config file password")
        if passwd is None:
            raise InvalidToken
        else:
            logger.debug(TKNACS_CLI_CONF)
            config = EncryptedConfig(
                fileName=TKNACS_CLI_CONF,
                key=passToKey(passwd=passwd),
            )
            config.setConfig(user=user)
            logger.info("Configuration created.")
    else:
        for chance in range(3,0,-1):
            try:
                passwd = getpass(f"Encryption password ({str(chance)} tests remaining): ")
                logger.debug(TKNACS_CLI_CONF)
                config = EncryptedConfig(
                    fileName=TKNACS_CLI_CONF,
                    key=passToKey(passwd=passwd),
                )
                logger.info("Configuration loaded.")
                break
            except:
                passKey = None
        
        if 'config' not in locals():
            logger.critical('3 erroneous passwords tries done, exiting.')
            raise InvalidToken


    # Main menu
    main_menu(config=config)
