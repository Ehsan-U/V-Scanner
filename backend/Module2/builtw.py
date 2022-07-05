
from multiprocessing import Process,Manager
from builtwith import builtwith
import argparse

manager = Manager()
return_dict = manager.dict()

parser = argparse.ArgumentParser()
parser.add_argument('-u',dest='url')
parser.add_argument('-a',dest='agent')
values = parser.parse_args()
args_dict = vars(values)

def bltwth(): # subprocess
    data = builtwith(args_dict.get('url'),user_agent=args_dict.get('agent'))
    return_dict['data'] = data
    return return_dict

if __name__ == '__main__':
    p = Process(target=bltwth)
    p.start()
    p.join(2)
    p.terminate()
    if p.exitcode == 0:
        print(return_dict['data'])
    elif p.exitcode == None:
        print(return_dict)