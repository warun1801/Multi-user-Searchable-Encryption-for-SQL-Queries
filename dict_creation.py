from collections import defaultdict
from pprint import pprint

# This will help us get all the keywords of a given table
def create_keyword_set(table):
    W = set()
    for row in table:
        for keyword in row:
            W.add(keyword)
    return W


# This will help us create the dictionary of rows for the given table and keyword set
def create_dictionary(table):
    A = defaultdict(list)
    for id, row in enumerate(table):
        for keyword in row:
            A[keyword].append(id)
    return A


def fetch_table(path):
    table = []
    cnt = 0
    with open(path, 'r') as f:
        for line in f:
            cnt+=1
            if cnt == 1:
                continue
            table.append(line.strip().split(','))
    return table

def get_table_info(table_name):
    table = fetch_table(table_name)
    W = create_keyword_set(table)
    A = create_dictionary(table)
    return table, W, A

if __name__ == "__main__":
    get_table_info()