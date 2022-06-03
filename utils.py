from functools import wraps
import re


def input_check(*args1):
    """
    This is a outer decorator to check user input type.

    Parameters
    ----------
    *args1 : tuple
        It is used to get expected input type for variables of a function
    Returns
    -------
    check : function
        Inner decorator that runs the provided function
    """

    def check(func):
        """

        Parameters
        ----------
        func : func
            Provided function that decorator will run.
        Returns
        -------
        wrap : func
            Wrapper function
        """
        def wrap(*args, **kwargs):
            """
            This wrap function checks if provided user inputs are equal to specified
            in outer decorator.


            Parameters
            ----------
            args : tuple
                Positional arguments of decorated function
            kwargs : dict
                Keyword arguments of decorated function

            Returns
            -------

            Raises
            ______


            """
            # print(args1,args,"ssss")
            dummylist = list(args)[1:] + list(kwargs.values())
            for c1, c2 in zip(list(args1), dummylist):
                if (c1 != type(c2)):
                    raise ("ERROR")
            func(*args, **kwargs)

        return wrap

    return check


def ssh_string_cleaner(ssh_output: str, start_str: str, splitter: str = "\r\n", split_type: str = "SPACE") -> list:
    """
    This function is used for converting ssh output to usable elements in a list.

    Parameters
    ----------
    ssh_output : str
            This variable is a string that returns from ssh session as a output
    start_str : str
            This variable is a string that specify the starting point of ssh_output
        variable.It is usually the command sent from ssh session.
    splitter : str
            This variable is used for splitting the multiline ssh_output.By default
        '\r\n' is used because Cisco uses '\r\n' for new line.
    split_type : str
            This variable is used for splitting lines produced by splitter split.There
        are three possible choices.
            SPACE-->split by ' ' and removes all ' ' from elements
            2+SPACE-->split by if two or more spaces exist in string and removes ' '
                    from elements
            COMMA-->split by ',' and strips the elements
            COLON-->split by ':' and strips the elements

    Returns
    -------
    line_list : list
    """

    line_list = ssh_output.strip().split(splitter)
    start_index = None
    for i, s in enumerate(line_list):
        if start_str[:-2] in s:
            start_index = i + 1
            break
    if start_index:
        if (split_type == "SPACE"):
            line_list = [[m2 for m2 in m.split(" ") if m2 != ""] for m in line_list[start_index:]]
        elif (split_type == "2+SPACE"):
            line_list = [[m2 for m2 in re.split("\s{2,}", m) if m2 != ""] for m in line_list[start_index:]]
        elif (split_type == "COMMA"):
            line_list = [[m2.strip() for m2 in m.split(",")] for m in line_list[start_index:]]
        elif (split_type == "COLON"):
            line_list = [[m2.strip() for m2 in m.split(":")] for m in line_list[start_index:]]
        elif (split_type == "NOSPLIT"):
            pass

    return line_list




class MyException(Exception):
    def __init__(self, *args):
        if args:
            self.message = args[0]
