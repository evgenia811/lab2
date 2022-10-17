import itertools
import multiprocessing
import os
import string
import time
from hashlib import sha256, md5

HASH_TYPES = {
    'sha256': lambda str_password: sha256(str_password.encode('utf-8')).hexdigest(),
    'md5': lambda str_password: md5(str_password.encode('utf-8')).hexdigest(),
}


def brute(list_first_symbol, hashes, hash_type):
    data = string.ascii_lowercase
    t_start_pass = time.perf_counter()
    for x in itertools.product(list_first_symbol, data, data, data, data):
        str_password = ''.join(x)
        hash_func = HASH_TYPES[hash_type]
        sha_code = hash_func(str_password)
        if sha_code in hashes:
            t_end_pass = time.perf_counter()
            t_calculation_pass = t_end_pass - t_start_pass
            print(
                f'{multiprocessing.current_process().name} ({list_first_symbol})\n\tХэш-значенияи {hash_type}:{sha_code}\n\tПароль: {str_password}\n\tВремя: {t_calculation_pass}')


def run_bruteforce(hash_type, file_name):
    with open(file_name) as file:
        all_hash_sha265 = [line.strip() for line in file]

    max_num_of_processes = os.cpu_count()
    while True:
        try:
            num_of_processes = int(
                input(f"Укажите целое количество потоков в диапазоне от 1 до {max_num_of_processes}: "))
            if 1 <= num_of_processes <= max_num_of_processes:
                break
            print("Введено недопустимое количество потоков")
        except ValueError:
            print("Введено не число / не целое число")

    size_block = len(string.ascii_lowercase) // num_of_processes
    num_max_block = len(string.ascii_lowercase) % num_of_processes
    print(string.ascii_lowercase)
    t_start = time.perf_counter()

    processes = []
    for np in range(num_of_processes):

        if np < num_max_block:
            list_first_symbol = string.ascii_lowercase[(size_block + 1) * np: (size_block + 1) * (np + 1)]
        else:
            list_first_symbol = string.ascii_lowercase[
                                (size_block + 1) * num_max_block + size_block * (np - num_max_block):
                                (size_block + 1) * num_max_block + size_block * (np - num_max_block + 1)]
        proc = multiprocessing.Process(target=brute, args=(list_first_symbol, all_hash_sha265, hash_type))
        proc.start()
        processes.append(proc)

    for proc in processes:
        proc.join()

    t_end = time.perf_counter()

    t_calculation = t_end - t_start

    print(f'Количество потоков - {num_of_processes}\nОбщее время подбора - {t_calculation}')


if __name__ == "__main__":
    print('Поиск для метода sha256')

    run_bruteforce('sha256',
                   "hash_functions_sha256.txt")

    print('\n\nПоиск для метода md5')
    run_bruteforce('md5',
                   "hash_functions_md5.txt")
