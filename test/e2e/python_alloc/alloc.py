def allocate_memory():
    try:
        memory_list = []
        while True:
            memory_list.append(" " * 1024 * 1024)
    except MemoryError:
        exit(0)

if __name__ == "__main__":
    allocate_memory()
