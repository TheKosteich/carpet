import contextlib
import os
import queue
import requests
import sys
import threading
import time

FILTERED = ['.jpg', '.gif', '.png', '.css']
TARGET = 'http://boodelyboo.com/wordpress'
THREADS = 10

answers = queue.Queue()
web_paths = queue.Queue()


def gather_paths():
    for root, _, files in os.walk('.'):
        for file_name in files:
            if os.path.splitext(file_name)[1] in FILTERED:
                continue
            path = os.path.join(root, file_name)
            if path.startswith('.'):
                path = path[1:]
            print(path)
            web_paths.put(path)


@contextlib.contextmanager
def chdir(path):
    """
    On enter, change directory to specified path.
    On exit, change directory back to original.
    :param path:
    :return: None
    """
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(this_dir)


def test_remote():
    while not web_paths.empty():
        path = web_paths.get()
        url = f'{TARGET}{path}'
        time.sleep(2)
        response = requests.get(url)
        if response.status_code == 200:
            answers.put(url)
            sys.stdout.write('+')
        else:
            sys.stdout.write('x')
        sys.stdout.flush()


def run():
    my_threads = list()
    for i in range(THREADS):
        print(f'Spawning thread {i}')
        thread = threading.Thread(target=test_remote)
        my_threads.append(thread)
        thread.start()

    for t in my_threads:
        t.join()


if __name__ == '__main__':
    with chdir('/tmp/wordpress'):
        gather_paths()
    input('Press return to continue.')

    run()
    with open('myanswers.txt', 'w') as file:
        while not answers.empty():
            file.write(f'{answers.get()}\n')
    print('done')
