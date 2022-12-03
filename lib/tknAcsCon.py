from logging import getLogger
logger = getLogger('tknAcsLogger')

from abc import ABC, abstractmethod


class TknAcsConnector(ABC):
    conType=None

    @abstractmethod
    def getTokenForUser(userName, userPass, recipient):
        pass

    @abstractmethod
    def getAllTokensForUser(userName, userPass):
        pass

    @abstractmethod
    def getAllTokenForUser(userName, userPass):
        pass

    @abstractmethod
    def setNewPsk(userName, userPass, publicKey) -> bytes:
        return None





class TknAcsConAPI(TknAcsConnector):
    pass