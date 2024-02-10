websites = []
    with open("suurls.csv", 'r') as file:
        lines = file.readlines()
        for line in lines:
            websites.append(line.rstrip())