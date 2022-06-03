from abc import ABCMeta, abstractmethod
import time, re
from Network.utils import ssh_string_cleaner, input_check, MyException

SSH_PORT = 22


class IPAddress:
    """This descriptor used in Network abstract class to check if user call valid ip address or not.

        If value count of '.' is not equal to 3, then it means not valid IP. Other check is if integer
    value of every octet is greater than 255 or not.
    """

    def __init__(self, ip: str):
        self.ip = ip

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__[self.ip]
        pass

    def __set__(self, instance, value):
        if (not isinstance(value, str)): raise MyException("*" * 10, "NOT A STRING", "*" * 10)
        if (value.count(".") != 3): raise MyException("*" * 10, "NOT AN IP ADDRESS", "*" * 10)
        _ = value.split(".")
        for i in _:
            try:
                if (len(bin(int(i))) < 11):
                    continue
                else:
                    raise MyException("*" * 10, "NOT AN IP ADDRESS", "*" * 10)
            except:
                raise MyException("*" * 10, "NOT AN IP ADDRESS", "*" * 10)
        instance.__dict__[self.ip] = value


class Network(metaclass=ABCMeta):
    """This class is main class for all network devices.

        Every subclass can use ssh,snmp and rest functions provided by this main
    class. This class can not be initiated directly.

    """
    ip = IPAddress('ip')
    @abstractmethod
    @input_check(str)
    def __init__(self, ip: str):
        self.vendor = str()
        self.model = str()
        self.ip = ip
        self.ssh_client = None
        self.snmp_community = None

    @input_check(str, str)
    def get_ssh(self, username: str, password: str, port: int = SSH_PORT):
        """This function is used to return ssh client object.

            Paramiko library is used and there is a input_check decorator to control type of value
        client gives to this function.

        Parameters
        ----------
        username: str
            Username for ssh session
        password: str
            Password for ssh session
        port : int
            Port number for ssh session. By default it is 22.

        Returns
        -------
            This function returns invoked shell fo given IP. With this returned value, ssh commands
        can be sent to device.
        """
        import paramiko
        print("SSH")
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        self.ssh_client.connect(hostname=self.ip, port=port, username=username,
                                password=password, look_for_keys=False, allow_agent=False,
                                timeout=10)
        self.ssh_client = self.ssh_client.invoke_shell(height=300)

    def __close_ssh__(self):
        import paramiko
        print("SSH CLOSED-1")
        self.ssh_client.close()
        print("SSH CLOSED-2")
    @abstractmethod
    def __get_rest__(self, username: str, password: str):
        print("REST")

    @input_check(str)
    def get_snmp(self, community: str):
        """This function is used to get community value for snmp

        Parameters
        ----------
        community : str

        """
        print("SNMP")
        self.snmp_community = community
