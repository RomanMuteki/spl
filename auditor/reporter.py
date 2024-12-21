import pandas as pd
import re


def process_first_file(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            match = re.match(r'^(\S+ \S+) - \S+ - (.*?): (.+)$', line)
            if match:
                timestamp, event, path = match.groups()
                data.append({'Время': timestamp, 'Событие': event, 'Путь': path})
    return pd.DataFrame(data)


def process_second_file(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            match = re.match(r'^(\S+ \S+) - \S+ - (TCP|UDP) соединение: (.+)$', line)
            if match:
                timestamp, protocol, connection = match.groups()
                data.append({'Время': timestamp, 'Протокол': protocol, 'Адрес': connection})
    return pd.DataFrame(data)


def process_third_file(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            match = re.match(r'^(\S+ \S+) - \S+ - Запущен процесс: PID=(\d+), команда: (.+)$', line)
            if match:
                timestamp, pid, command = match.groups()
                data.append({'Время': timestamp, 'PID': pid, 'Команда': command})
    return pd.DataFrame(data)


def create_excel_report(first_file, second_file, third_file, output_file):
    df1 = process_first_file(first_file)
    df2 = process_second_file(second_file)
    df3 = process_third_file(third_file)

    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        df1.to_excel(writer, index=False, sheet_name='Файлы')
        df2.to_excel(writer, index=False, sheet_name='Сети')
        df3.to_excel(writer, index=False, sheet_name='Процессы')

    print(f"Отчет успешно сохранен в {output_file}")


first_file_path = 'file_system_log.txt'
second_file_path = 'network_log.txt'
third_file_path = 'process_log.txt' 
output_file_path = 'report.xlsx'


create_excel_report(first_file_path, second_file_path, third_file_path, output_file_path)

